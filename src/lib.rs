use bytes::Bytes;
use h264::{Bitstream, Decode, NALUnit, SequenceParameterSet};
use std::io::{self, Error, ErrorKind};
use std::time::Duration;

// This represents an upper bound on the number of bytes needed to read from a slice
// to extract the Picture Order Count, considering Exponential-Golomb coding.
const MAX_BYTES_TO_GET_POC: usize = 22;
const MAX_REORDERED_FRAMES: i32 = 10;

fn remove_emulation_prevention_bytes(buf: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(buf.len());
    let mut i = 0;

    while i < buf.len() {
        if i + 2 < buf.len() && buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 2] == 0x03 {
            // Copy up to the emulation prevention byte.
            output.extend_from_slice(&buf[i..i + 2]);
            i += 3; // Skip the 0x00 0x00 0x03 sequence
        } else {
            output.push(buf[i]);
            i += 1;
        }
    }

    output
}

// Function to extract the picture order count (POC) from a NAL unit
fn get_picture_order_count(buf: &[u8], sps: &SequenceParameterSet) -> io::Result<u32> {
    if buf.len() < 2 {
        // Ensure there's enough data to skip the NALU header
        return Err(Error::new(ErrorKind::InvalidData, "Buffer too short"));
    }

    // Skip the NALU header and limit the buffer if necessary
    let mut buf = &buf[1..];
    let lb = buf.len().min(MAX_BYTES_TO_GET_POC);
    buf = &buf[..lb];

    // Remove emulation prevention bytes to get valid RBSP
    let buf = remove_emulation_prevention_bytes(buf);

    // Create a new Bitstream for reading
    let mut bs = Bitstream::new(buf.into_iter());

    // Reading syntax elements from the slice header
    let _first_mb_in_slice = bs.read_ue()?;
    let _slice_type = bs.read_ue()?;
    let _pic_parameter_set_id = bs.read_ue()?;

    bs.advance_bits((sps.log2_max_frame_num_minus4.0 as usize) + 4);
    let pic_order_cnt_lsb = bs.read_bits((sps.log2_max_pic_order_cnt_lsb_minus4.0 as usize) + 4)?;

    Ok(pic_order_cnt_lsb as u32)
}

fn get_picture_order_count_diff(a: u32, b: u32, sps: &SequenceParameterSet) -> i32 {
    let max = 1u32 << (sps.log2_max_pic_order_cnt_lsb_minus4.0 + 4);
    let d = (a.wrapping_sub(b)) & (max - 1);
    if d > (max / 2) {
        return d as i32 - max as i32;
    }
    d as i32
}

#[derive(Debug, Clone)]
pub struct DtsExtractor {
    expected_poc: u32,
    prev_dts: Option<Duration>,
    reordered_frames: i32,
    pause_dts: i32,
    poc_increment: i32,
    sps: Option<SequenceParameterSet>,
}

impl DtsExtractor {
    pub fn new() -> Self {
        Self {
            expected_poc: 0,
            prev_dts: None,
            reordered_frames: 0,
            pause_dts: 0,
            poc_increment: 2,
            sps: None,
        }
    }

    pub fn set_sps(&mut self, sps_b: &Bytes) -> bool {
        let bs = Bitstream::new(sps_b.iter().copied());
        if let Ok(mut nalu) = NALUnit::decode(bs) {
            let mut rbsp = Bitstream::new(&mut nalu.rbsp_byte);
            if let Ok(sps) = SequenceParameterSet::decode(&mut rbsp) {
                self.sps = Some(sps);
            }
        }

        self.sps.is_some()
    }

    pub fn extract(&mut self, nalu: &[u8], pts: Duration, is_idr: bool) -> io::Result<Duration> {
        if self.sps.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SPS not set!"));
        }

        let (dts, skip_checks) = self.extract_inner(nalu, pts, is_idr)?;

        if !skip_checks && dts > pts {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DTS is greater than PTS",
            ));
        }

        if let Some(prev_dts) = self.prev_dts {
            if dts < prev_dts {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "DTS is not monotonically increasing, was {:?}, now is {:?}",
                        prev_dts, dts
                    ),
                ));
            }
        }

        self.prev_dts = Some(dts);

        Ok(dts)
    }

    fn extract_inner(
        &mut self,
        au: &[u8],
        pts: Duration,
        is_idr: bool,
    ) -> io::Result<(Duration, bool)> {
        let sps = self.sps.as_ref().unwrap();
        if sps.pic_order_cnt_type.0 == 2 || sps.frame_mbs_only_flag.0 == 0 {
            // If PicOrderCntType is 2 or FrameMbsOnlyFlag is false, return PTS as is
            return Ok((pts, false));
        }

        if sps.pic_order_cnt_type.0 == 1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "pic_order_cnt_type = 1 is not supported",
            ));
        }

        if is_idr {
            self.expected_poc = 0;
            self.pause_dts = 0;

            if self.prev_dts.is_none() || self.reordered_frames == 0 {
                return Ok((pts, false));
            }

            let prev_dts = self.prev_dts.unwrap();

            return Ok((
                prev_dts + (pts - prev_dts) / (self.reordered_frames + 1) as u32,
                false,
            ));
        } else {
            self.expected_poc += self.poc_increment as u32;
            // Ensure expected_poc wraps correctly based on Log2MaxPicOrderCntLsbMinus4
            let max_poc_lsb = 1 << (sps.log2_max_pic_order_cnt_lsb_minus4.0 + 4);
            self.expected_poc &= (max_poc_lsb - 1) as u32;

            let prev_dts = self.prev_dts.unwrap_or(Duration::from_millis(0));

            if self.pause_dts > 0 {
                self.pause_dts -= 1;
                return Ok((prev_dts + Duration::from_millis(1), true));
            }

            let poc = get_picture_order_count(&au, &sps)?;

            if self.poc_increment == 2 && (poc % 2) != 0 {
                self.poc_increment = 1;
                self.expected_poc /= 2;
            }

            let poc_diff =
                get_picture_order_count_diff(poc, self.expected_poc, &sps) / self.poc_increment;
            let limit = -(self.reordered_frames + 1);

            if poc_diff < limit {
                let increase = limit - poc_diff;
                self.reordered_frames += increase;
                self.pause_dts = increase;
                return Ok((prev_dts + Duration::from_millis(1), true));
            }

            if poc_diff == limit {
                return Ok((pts, false));
            }

            if poc_diff > self.reordered_frames {
                let increase = poc_diff - self.reordered_frames;
                if (self.reordered_frames + increase) > MAX_REORDERED_FRAMES {
                    return Ok((Duration::from_millis(0), false));
                }

                self.reordered_frames += increase;
                self.pause_dts = increase - 1;

                return Ok((prev_dts + Duration::from_millis(1), false));
            }

            if pts < prev_dts {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pts is less than prev_pts, indicating an invalid state",
                ));
            }

            let new_dts = prev_dts
                .checked_add((pts - prev_dts) / (poc_diff + self.reordered_frames + 1) as u32)
                .expect("Overflow when computing new_dts");

            return Ok((new_dts, false));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct DtsSample {
        au: Vec<u8>,
        dts: Duration,
        pts: Duration,
    }

    struct PocSample {
        sps: Vec<u8>,
        au: Vec<u8>,
        poc: u32,
    }

    struct DiffSample {
        sps: Vec<u8>,
        poc: u32,
        expected_poc: u32,
        got: i32,
    }

    #[test]
    fn test_emulation_prevention_remove() {
        let cases = vec![
            (
                "base",
                vec![
                    0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x03, 0x02, 0x00,
                    0x00, 0x03, 0x03,
                ],
                vec![
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03,
                ],
            ),
            (
                "double emulation byte",
                vec![0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03],
                vec![0x00, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                "terminal emulation byte",
                vec![0x00, 0x00, 0x03],
                vec![0x00, 0x00],
            ),
        ];

        for (name, proc, unproc) in cases {
            let result = remove_emulation_prevention_bytes(&proc);
            assert_eq!(result, unproc, "Case failed: {}", name);
        }
    }

    #[test]
    fn test_get_picture_order_count() {
        let samples = vec![
            PocSample {
                au: vec![0x41, 0x9a, 0x21, 0x6c, 0x45, 0xff],
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 2,
            },
            PocSample {
                au: vec![0x41, 0x9a, 0x42, 0x3c, 0x21, 0x93],
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 4,
            },
            PocSample {
                au: vec![0x41, 0x9a, 0x63, 0x49, 0xe1, 0x0f],
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 6,
            },
            PocSample {
                au: vec![0x41, 0x9a, 0x86, 0x49, 0xe1, 0x0f],
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 12,
            },
            PocSample {
                au: vec![0x01, 0x9e, 0xc4, 0x69, 0x13, 0xff],
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 8,
            },
            PocSample {
                au: vec![0x41, 0x9a, 0xc8, 0x4b, 0xa8, 0x42],
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 16,
            },
            PocSample {
                au: vec![0x21, 0xe1, 0x05, 0xc7, 0x38, 0xbf],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 2,
            },
            PocSample {
                au: vec![0x21, 0xe2, 0x09, 0xa1, 0xce, 0x0b],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 4,
            },
            PocSample {
                au: vec![0x21, 0xe3, 0x0d, 0xb1, 0xce, 0x02],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 6,
            },
            PocSample {
                au: vec![0x21, 0xe4, 0x11, 0x90, 0x73, 0x80],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 8,
            },
            PocSample {
                au: vec![0x21, 0xe5, 0x19, 0x0e, 0x70, 0x01],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 12,
            },
            PocSample {
                au: vec![0x01, 0xa9, 0x85, 0x7c, 0x93, 0xff],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 10,
            },
            PocSample {
                au: vec![0x21, 0xe6, 0x1d, 0x0e, 0x70, 0x01],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 14,
            },
            PocSample {
                au: vec![0x21, 0xe7, 0x21, 0x0e, 0x70, 0x01],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 16,
            },
            PocSample {
                au: vec![0x21, 0xe8, 0x25, 0x0e, 0x70, 0x01],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 18,
            },
            PocSample {
                au: vec![0x21, 0xe9, 0x29, 0x0e, 0x70, 0x01],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 20,
            },
            PocSample {
                au: vec![0x21, 0xea, 0x31, 0x0e, 0x70, 0x01],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 24,
            },
            PocSample {
                au: vec![0x01, 0xaa, 0xcb, 0x7c, 0x93, 0xff],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 22,
            },
            PocSample {
                au: vec![0x61, 0xe0, 0x20, 0x00, 0x39, 0x37],
                sps: vec![
                    0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e,
                    0x02, 0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02,
                ],
                poc: 1,
            },
            PocSample {
                au: vec![0x61, 0xe0, 0x40, 0x00, 0x59, 0x37],
                sps: vec![
                    0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e,
                    0x02, 0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02,
                ],
                poc: 2,
            },
            PocSample {
                au: vec![0x61, 0xe0, 0x60, 0x00, 0x79, 0x37],
                sps: vec![
                    0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e,
                    0x02, 0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02,
                ],
                poc: 3,
            },
            PocSample {
                au: vec![0x41, 0x9e, 0x03, 0xe4, 0x3f, 0x00, 0x00, 0x03, 0x00, 0x00],
                sps: vec![
                    0x27, 0x64, 0x00, 0x2a, 0xac, 0x2d, 0x90, 0x07, 0x80, 0x22, 0x7e, 0x5c, 0x05,
                    0xa8, 0x08, 0x08, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00,
                    0xf1, 0xd0, 0x80, 0x04, 0xc4, 0x80, 0x00, 0x09, 0x89, 0x68, 0xde, 0xf7, 0xc1,
                    0xda, 0x1c, 0x31, 0x92,
                ],
                poc: 60,
            },
            PocSample {
                au: vec![0x01, 0x9e, 0x05, 0xf4, 0x7f, 0x00, 0x00, 0x03, 0x00, 0x00],
                sps: vec![
                    0x27, 0x64, 0x00, 0x2a, 0xac, 0x2d, 0x90, 0x07, 0x80, 0x22, 0x7e, 0x5c, 0x05,
                    0xa8, 0x08, 0x08, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00,
                    0xf1, 0xd0, 0x80, 0x04, 0xc4, 0x80, 0x00, 0x09, 0x89, 0x68, 0xde, 0xf7, 0xc1,
                    0xda, 0x1c, 0x31, 0x92,
                ],
                poc: 62,
            },
            PocSample {
                au: vec![0x61, 0x00, 0xf0, 0xe0, 0x00, 0x40, 0x00, 0xbe, 0x47, 0x9b],
                sps: vec![
                    0x67, 0x42, 0xc0, 0x1e, 0x8c, 0x8d, 0x40, 0x50, 0x17, 0xfc, 0xb0, 0x0f, 0x08,
                    0x84, 0x6a,
                ],
                poc: 2,
            },
            PocSample {
                au: vec![0x41, 0x30, 0x30, 0x30, 0x30, 0x30],
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 96,
            },
        ];

        for sample in samples {
            let sps_bytes = &sample.sps;
            let bs = Bitstream::new(sps_bytes.iter().copied());
            if let Ok(mut nalu) = NALUnit::decode(bs) {
                let mut rbsp = Bitstream::new(&mut nalu.rbsp_byte);
                if let Ok(sps) = SequenceParameterSet::decode(&mut rbsp) {
                    let poc = get_picture_order_count(&sample.au, &sps).unwrap();
                    assert_eq!(poc, sample.poc, "POC did not match");
                }
            }
        }
    }

    #[test]
    fn test_get_picture_order_count_diff() {
        let samples = vec![
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 2,
                expected_poc: 2,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 4,
                expected_poc: 4,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 6,
                expected_poc: 6,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 12,
                expected_poc: 8,
                got: 4,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 8,
                expected_poc: 12,
                got: -4,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00,
                    0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
                ],
                poc: 16,
                expected_poc: 14,
                got: 2,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 2,
                expected_poc: 2,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 4,
                expected_poc: 4,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 6,
                expected_poc: 6,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 8,
                expected_poc: 8,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 12,
                expected_poc: 10,
                got: 2,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 10,
                expected_poc: 12,
                got: -2,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 14,
                expected_poc: 14,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 16,
                expected_poc: 16,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 18,
                expected_poc: 18,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 20,
                expected_poc: 20,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 24,
                expected_poc: 22,
                got: 2,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 22,
                expected_poc: 24,
                got: -2,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e,
                    0x02, 0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02,
                ],
                poc: 1,
                expected_poc: 1,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e,
                    0x02, 0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02,
                ],
                poc: 2,
                expected_poc: 2,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e,
                    0x02, 0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02,
                ],
                poc: 3,
                expected_poc: 3,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x2a, 0xac, 0x2d, 0x90, 0x07, 0x80, 0x22, 0x7e, 0x5c, 0x05,
                    0xa8, 0x08, 0x08, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00,
                    0xf1, 0xd0, 0x80, 0x04, 0xc4, 0x80, 0x00, 0x09, 0x89, 0x68, 0xde, 0xf7, 0xc1,
                    0xda, 0x1c, 0x31, 0x92,
                ],
                poc: 60,
                expected_poc: 2,
                got: -6,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x2a, 0xac, 0x2d, 0x90, 0x07, 0x80, 0x22, 0x7e, 0x5c, 0x05,
                    0xa8, 0x08, 0x08, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00,
                    0xf1, 0xd0, 0x80, 0x04, 0xc4, 0x80, 0x00, 0x09, 0x89, 0x68, 0xde, 0xf7, 0xc1,
                    0xda, 0x1c, 0x31, 0x92,
                ],
                poc: 62,
                expected_poc: 8,
                got: -10,
            },
            DiffSample {
                sps: vec![
                    0x67, 0x42, 0xc0, 0x1e, 0x8c, 0x8d, 0x40, 0x50, 0x17, 0xfc, 0xb0, 0x0f, 0x08,
                    0x84, 0x6a,
                ],
                poc: 2,
                expected_poc: 2,
                got: 0,
            },
            DiffSample {
                sps: vec![
                    0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00,
                    0x01, 0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
                ],
                poc: 96,
                expected_poc: 8,
                got: -40,
            },
        ];

        for sample in samples {
            let sps_bytes = &sample.sps;
            let bs = Bitstream::new(sps_bytes.iter().copied());
            if let Ok(mut nalu) = NALUnit::decode(bs) {
                let mut rbsp = Bitstream::new(&mut nalu.rbsp_byte);
                if let Ok(sps) = SequenceParameterSet::decode(&mut rbsp) {
                    let diff = get_picture_order_count_diff(sample.poc, sample.expected_poc, &sps);
                    assert_eq!(diff, sample.got, "POC Diff did not match");
                }
            }
        }
    }

    #[test]
    fn test_dts_extractor_with_timing_info() {
        let sps = vec![
            0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0x84, 0x00, 0x00,
            0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x3c, 0x60, 0xc6, 0x58,
        ];
        let samples = vec![
            DtsSample {
                au: vec![0x65, 0x88, 0x84, 0x00, 0x33, 0xff],
                dts: Duration::from_nanos(333333333),
                pts: Duration::from_nanos(333333333),
            },
            DtsSample {
                au: vec![0x41, 0x9a, 0x21, 0x6c, 0x45, 0xff],
                dts: Duration::from_nanos(366666666),
                pts: Duration::from_nanos(366666666),
            },
            DtsSample {
                au: vec![0x41, 0x9a, 0x42, 0x3c, 0x21, 0x93],
                dts: Duration::from_nanos(400000000),
                pts: Duration::from_nanos(400000000),
            },
            DtsSample {
                au: vec![0x41, 0x9a, 0x63, 0x49, 0xe1, 0x0f],
                dts: Duration::from_nanos(433333333),
                pts: Duration::from_nanos(433333333),
            },
            DtsSample {
                au: vec![0x41, 0x9a, 0x86, 0x49, 0xe1, 0x0f],
                dts: Duration::from_nanos(434333333),
                pts: Duration::from_nanos(533333333),
            },
            DtsSample {
                au: vec![0x41, 0x9e, 0xa5, 0x42, 0x7f, 0xf9],
                dts: Duration::from_nanos(435333333),
                pts: Duration::from_nanos(500000000),
            },
            DtsSample {
                au: vec![0x01, 0x9e, 0xc4, 0x69, 0x13, 0xff],
                dts: Duration::from_nanos(466666666),
                pts: Duration::from_nanos(466666666),
            },
            DtsSample {
                au: vec![0x41, 0x9a, 0xc8, 0x4b, 0xa8, 0x42],
                dts: Duration::from_nanos(499999999),
                pts: Duration::from_nanos(600000000),
            },
            DtsSample {
                au: vec![0x65, 0x88, 0x84, 0x00, 0x33, 0xff],
                dts: Duration::from_nanos(533333332),
                pts: Duration::from_nanos(599999999),
            },
        ];

        let mut au = AuPayload::new();
        let mut dts_extractor = DtsExtractor::new();
        dts_extractor.set_sps(&Bytes::from(sps));
        for sample in samples {
            let is_idr = (sample.au[0] & h264::NAL_UNIT_TYPE_MASK) == 5;
            let dts = dts_extractor
                .extract(&sample.au, sample.pts, is_idr)
                .unwrap();
            assert_eq!(
                dts,
                sample.dts,
                "DTS extraction did not match expected value for dts: {} pts: {}",
                sample.dts.as_nanos(),
                sample.pts.as_nanos(),
            );
        }
    }

    #[test]
    fn test_dts_extractor_no_timing_info() {
        let sps = vec![
            0x27, 0x64, 0x00, 0x20, 0xac, 0x52, 0x18, 0x0f, 0x01, 0x17, 0xef, 0xff, 0x00, 0x01,
            0x00, 0x01, 0x6a, 0x02, 0x02, 0x03, 0x6d, 0x85, 0x6b, 0xde, 0xf8, 0x08,
        ];

        let samples = vec![
            DtsSample {
                au: vec![0x25, 0xb8, 0x08, 0x02, 0x1f, 0xff],
                dts: Duration::from_nanos(850_000_000),
                pts: Duration::from_nanos(850_000_000),
            },
            DtsSample {
                au: vec![0x21, 0xe1, 0x05, 0xc7, 0x38, 0xbf],
                dts: Duration::from_nanos(866_666_667),
                pts: Duration::from_nanos(866_666_667),
            },
            DtsSample {
                au: vec![0x21, 0xe2, 0x09, 0xa1, 0xce, 0x0b],
                dts: Duration::from_nanos(883_333_334),
                pts: Duration::from_nanos(883_333_334),
            },
            DtsSample {
                au: vec![0x21, 0xe3, 0x0d, 0xb1, 0xce, 0x02],
                dts: Duration::from_nanos(900_000_000),
                pts: Duration::from_nanos(900_000_000),
            },
            DtsSample {
                au: vec![0x21, 0xe4, 0x11, 0x90, 0x73, 0x80],
                dts: Duration::from_nanos(916_666_667),
                pts: Duration::from_nanos(916_666_667),
            },
            DtsSample {
                au: vec![0x21, 0xe5, 0x19, 0x0e, 0x70, 0x01],
                dts: Duration::from_nanos(917_666_667),
                pts: Duration::from_nanos(950_000_000),
            },
            DtsSample {
                au: vec![0x01, 0xa9, 0x85, 0x7c, 0x93, 0xff],
                dts: Duration::from_nanos(933_333_334),
                pts: Duration::from_nanos(933_333_334),
            },
            DtsSample {
                au: vec![0x21, 0xe6, 0x1d, 0x0e, 0x70, 0x01],
                dts: Duration::from_nanos(950_000_000),
                pts: Duration::from_nanos(966_666_667),
            },
            DtsSample {
                au: vec![0x21, 0xe7, 0x21, 0x0e, 0x70, 0x01],
                dts: Duration::from_nanos(966_666_667),
                pts: Duration::from_nanos(983_333_334),
            },
            DtsSample {
                au: vec![0x21, 0xe8, 0x25, 0x0e, 0x70, 0x01],
                dts: Duration::from_nanos(983_333_333),
                pts: Duration::from_nanos(1_000_000_000),
            },
            DtsSample {
                au: vec![0x21, 0xe9, 0x29, 0x0e, 0x70, 0x01],
                dts: Duration::from_nanos(1_000_000_000),
                pts: Duration::from_nanos(1_016_666_667),
            },
            DtsSample {
                au: vec![0x21, 0xea, 0x31, 0x0e, 0x70, 0x01],
                dts: Duration::from_nanos(1_016_666_666),
                pts: Duration::from_nanos(1_050_000_000),
            },
            DtsSample {
                au: vec![0x01, 0xaa, 0xcb, 0x7c, 0x93, 0xff],
                dts: Duration::from_nanos(1_033_333_334),
                pts: Duration::from_nanos(1_033_333_334),
            },
        ];

        let mut au = AuPayload::new();
        let mut dts_extractor = DtsExtractor::new();
        dts_extractor.set_sps(&Bytes::from(sps));
        for sample in samples {
            let is_idr = (sample.au[0] & h264::NAL_UNIT_TYPE_MASK) == 5;
            let dts = dts_extractor
                .extract(&sample.au, sample.pts, is_idr)
                .unwrap();
            assert_eq!(
                dts, sample.dts,
                "DTS extraction did not match expected value for dts: {:?} pts: {:?}",
                sample.dts, sample.pts
            );
        }
    }

    #[test]
    fn test_dts_extractor_poc_increment_1() {
        let sps = vec![
            0x67, 0x64, 0x00, 0x2a, 0xac, 0x2c, 0x6a, 0x81, 0xe0, 0x08, 0x9f, 0x96, 0x6e, 0x02,
            0x02, 0x02, 0x80, 0x00, 0x03, 0x84, 0x00, 0x00, 0xaf, 0xc8, 0x02, 0x65, 0xb8, 0x00,
            0x00, 0x0b, 0xc8,
        ];

        let samples = vec![
            DtsSample {
                au: vec![0x65, 0xb8, 0x00, 0x00, 0x0b, 0xc8],
                dts: Duration::from_millis(61),
                pts: Duration::from_millis(61),
            },
            DtsSample {
                au: vec![0x61, 0xe0, 0x20, 0x00, 0x39, 0x37],
                dts: Duration::from_millis(101),
                pts: Duration::from_millis(101),
            },
            DtsSample {
                au: vec![0x61, 0xe0, 0x40, 0x00, 0x59, 0x37],
                dts: Duration::from_millis(141),
                pts: Duration::from_millis(141),
            },
            DtsSample {
                au: vec![0x61, 0xe0, 0x60, 0x00, 0x79, 0x37],
                dts: Duration::from_millis(181),
                pts: Duration::from_millis(181),
            },
        ];

        let mut au = AuPayload::new();
        let mut dts_extractor = DtsExtractor::new();
        dts_extractor.set_sps(&Bytes::from(sps));
        for sample in samples {
            let is_idr = (sample.au[0] & h264::NAL_UNIT_TYPE_MASK) == 5;
            let dts = dts_extractor
                .extract(&sample.au, sample.pts, is_idr)
                .unwrap();
            assert_eq!(
                dts, sample.dts,
                "DTS extraction did not match expected value for dts: {:?} pts: {:?}",
                sample.dts, sample.pts
            );
        }
    }

    #[test]
    fn test_dts_extractor_b_frames_after_idr() {
        let sps = vec![
            0x27, 0x64, 0x00, 0x2a, 0xac, 0x2d, 0x90, 0x07, 0x80, 0x22, 0x7e, 0x5c, 0x05, 0xa8,
            0x08, 0x08, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0xf1, 0xd0,
            0x80, 0x04, 0xc4, 0x80, 0x00, 0x09, 0x89, 0x68, 0xde, 0xf7, 0xc1, 0xda, 0x1c, 0x31,
            0x92,
        ];
        let samples = vec![
            DtsSample {
                // IDR
                au: vec![0x65, 0x88, 0x80, 0x14, 0x3, 0xff, 0xde, 0x8, 0xe4, 0x74],
                dts: Duration::from_millis(1916),
                pts: Duration::from_millis(1916),
            },
            DtsSample {
                // b-frame
                au: vec![0x41, 0x9e, 0x03, 0xe4, 0x3f, 0x00, 0x00, 0x03, 0x00, 0x00],
                dts: Duration::from_millis(1917),
                pts: Duration::from_millis(1883),
            },
            DtsSample {
                // b-frame
                au: vec![0x01, 0x9e, 0x05, 0xd4, 0x7f, 0x00, 0x00, 0x03, 0x00, 0x00],
                dts: Duration::from_millis(1918),
                pts: Duration::from_millis(1867),
            },
            DtsSample {
                // p-frame
                au: vec![0x01, 0x9e, 0x05, 0xf4, 0x7f, 0x00, 0x00, 0x03, 0x00, 0x00],
                dts: Duration::from_millis(1919),
                pts: Duration::from_millis(1899),
            },
            DtsSample {
                // p-frame
                au: vec![0x01, 0x9e, 0x05, 0xf4, 0x7f, 0x00, 0x00, 0x03, 0x00, 0x00],
                dts: Duration::from_millis(1920),
                pts: Duration::from_millis(1983),
            },
        ];

        let mut au = AuPayload::new();
        let mut dts_extractor = DtsExtractor::new();
        dts_extractor.set_sps(&Bytes::from(sps));
        for sample in samples {
            let is_idr = (sample.au[0] & h264::NAL_UNIT_TYPE_MASK) == 5;
            let dts = dts_extractor
                .extract(&sample.au, sample.pts, is_idr)
                .unwrap();
            assert_eq!(
                dts, sample.dts,
                "DTS extraction did not match expected value for dts: {:?} pts: {:?}",
                sample.dts, sample.pts
            );
        }
    }
}
