use crate::constants::character_string::MAX_OCTETS;
use crate::protocol::DomainName;
use crate::wire::{Result, WireError};

/// DNS message writer with RFC 1035 name-compression state.
#[derive(Debug)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
    name_offsets: super::compression::CompressionOffsets,
    compress_names: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            bytes: Vec::with_capacity(128),
            name_offsets: super::compression::CompressionOffsets::default(),
            compress_names: true,
        }
    }
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            name_offsets: super::compression::CompressionOffsets::default(),
            compress_names: true,
        }
    }
    pub(crate) fn new_uncompressed() -> Self {
        Self::from_uncompressed_bytes(Vec::with_capacity(128))
    }
    /// Continues a checked packet without emitting compression pointers. This
    /// encoder cannot subsequently enable compression or rewrite prior bytes.
    pub(crate) fn from_uncompressed_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            compress_names: false,
            name_offsets: super::compression::CompressionOffsets::default(),
        }
    }
    pub(crate) fn position(&self) -> usize {
        self.bytes.len()
    }
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    pub(crate) fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn write_u48(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes()[2..]);
    }
    pub(crate) fn write_exact(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn write_character_string(&mut self, value: &[u8]) -> Result<()> {
        if value.len() > MAX_OCTETS {
            return Err(WireError::LengthOverflow {
                field: "character-string",
                length: value.len(),
                maximum: MAX_OCTETS,
            });
        }
        self.write_u8(value.len() as u8);
        self.write_exact(value);
        Ok(())
    }

    pub(crate) fn write_name(&mut self, name: &DomainName) -> Result<()> {
        if !self.compress_names {
            self.write_uncompressed_name(name);
            return Ok(());
        }
        let labels = name.as_ref();
        let mut packed = [0; 255];
        let mut packed_len = 0;
        for label in labels {
            packed[packed_len] = label.len() as u8;
            packed_len += 1;
            packed[packed_len..packed_len + label.len()].copy_from_slice(label);
            packed_len += label.len();
        }
        let packed = &packed[..packed_len + 1];

        let mut suffix_start = 0;
        for label in labels {
            let suffix = &packed[suffix_start..];
            let target = (self.position() <= 0x3fff).then_some(self.position() as u16);
            if let Some(offset) = self.name_offsets.get_or_insert(suffix, target) {
                self.write_u16(0xc000 | offset);
                return Ok(());
            }
            self.write_u8(label.len() as u8);
            self.write_exact(label);
            suffix_start += 1 + label.len();
        }
        self.write_u8(0);
        Ok(())
    }

    /// Writes a complete domain name without substituting compression pointers.
    /// In a compressed writer, literal labels remain targets for later names.
    pub(crate) fn write_uncompressed_name(&mut self, name: &DomainName) {
        let labels = name.as_ref();
        // A permanently uncompressed writer never consults this dictionary.
        // Keep ordinary compressed writers' first-target registration intact,
        // including uncompressed SIG/RRSIG signer names.
        if !self.compress_names {
            for label in labels {
                self.write_u8(label.len() as u8);
                self.write_exact(label);
            }
            self.write_u8(0);
            return;
        }
        let mut packed = [0; 255];
        let mut packed_len = 0;
        for label in labels {
            packed[packed_len] = label.len() as u8;
            packed_len += 1;
            packed[packed_len..packed_len + label.len()].copy_from_slice(label);
            packed_len += label.len();
        }
        let packed = &packed[..packed_len + 1];

        let mut suffix_start = 0;
        for label in labels {
            let position = self.position();
            if position <= 0x3fff {
                self.name_offsets
                    .insert(&packed[suffix_start..], position as u16);
            }
            self.write_u8(label.len() as u8);
            self.write_exact(label);
            suffix_start += 1 + label.len();
        }
        self.write_u8(0);
    }

    pub(crate) fn write_rdata(
        &mut self,
        write: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let start = self.position();
        self.write_u16(0);
        let rdata_start = self.position();

        let result = write(self).and_then(|()| {
            let length = self.position() - rdata_start;
            let length = u16::try_from(length).map_err(|_| WireError::LengthOverflow {
                field: "RDATA",
                length,
                maximum: u16::MAX as usize,
            })?;

            self.bytes[start..start + 2].copy_from_slice(&length.to_be_bytes());
            Ok(())
        });

        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.bytes.truncate(start);
                // Encoding only adds previously absent suffixes. Every new
                // target lies inside the discarded RDATA, so rollback needs
                // no snapshot of the existing compression dictionary.
                self.name_offsets.retain_before(start);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod compression_oracle;

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&[u8]]) -> DomainName {
        DomainName::from_labels(labels.iter().map(|label| label.to_vec()).collect()).unwrap()
    }

    /// RFC 1035 §4.1.4: "a list of labels at the end of a domain name is
    /// replaced with a pointer to a prior occurance of the same name", so a
    /// later name whose suffix matches an earlier name must compress to a
    /// pointer to that suffix rather than repeating the labels.
    #[test]
    fn compresses_a_name_to_a_prior_name_suffix() {
        let mut encoder = Encoder::new();
        encoder
            .write_name(&name(&[b"www", b"example", b"com"]))
            .unwrap();
        let suffix_offset = encoder.position();
        encoder.write_name(&name(&[b"example", b"com"])).unwrap();

        let bytes = encoder.into_bytes();
        assert_eq!(suffix_offset, 17); // after "www.example.com"
        assert_eq!(
            &bytes[17..],
            &[0xc0, 0x04],
            "the suffix must be a pointer to offset 4"
        );
    }

    /// RFC 1035 §4.1.4: the pointer OFFSET field is 14 bits, so offsets above
    /// 0x3fff are unrepresentable and must never be used as pointer targets.
    #[test]
    fn compresses_at_the_largest_pointer_offset_but_not_beyond_it() {
        let write = |padding: usize| {
            let mut encoder = Encoder::new();
            let padding_bytes = vec![0; padding];
            encoder.write_exact(&padding_bytes);
            encoder.write_name(&name(&[b"edge"])).unwrap();
            encoder.write_name(&name(&[b"edge"])).unwrap();
            encoder.into_bytes()
        };

        // Offset 0x3fff is the largest value representable in the OFFSET field.
        let at_limit = write(0x3fff);
        assert_eq!(
            &at_limit[0x3fff..0x3fff + 6],
            &[4, b'e', b'd', b'g', b'e', 0]
        );
        assert_eq!(&at_limit[0x3fff + 6..], &[0xff, 0xff], "pointer to 0x3fff");

        // Offset 0x4000 cannot be pointed at; the repeat must stay literal.
        let past_limit = write(0x4000);
        assert_eq!(
            &past_limit[0x4000..0x4000 + 12],
            &[4, b'e', b'd', b'g', b'e', 0, 4, b'e', b'd', b'g', b'e', 0]
        );
    }

    #[test]
    fn failed_rdata_does_not_leave_compression_targets_in_discarded_bytes() {
        for overflow in [false, true] {
            let previous = name(&[b"www", b"example", b"test"]);
            let added = name(&[b"added", b"example", b"test"]);
            let mut encoder = Encoder::new();
            encoder.write_name(&previous).unwrap();
            let result = encoder.write_rdata(|encoder| {
                // Existing targets must survive even if repeated literally.
                encoder.write_uncompressed_name(&previous);
                encoder.write_name(&added)?;
                if overflow {
                    encoder.write_exact(&vec![0; u16::MAX as usize + 1]);
                    Ok(())
                } else {
                    Err(WireError::InvalidRData {
                        record_type: "test",
                        detail: "rollback",
                    })
                }
            });
            assert!(result.is_err());
            encoder.write_name(&added).unwrap();
            encoder.write_name(&previous).unwrap();

            let mut reference = Encoder::new();
            reference.write_name(&previous).unwrap();
            reference.write_name(&added).unwrap();
            reference.write_name(&previous).unwrap();
            assert_eq!(encoder.into_bytes(), reference.into_bytes());
        }
    }

    #[test]
    fn nested_rdata_rollback_retains_the_outer_transaction_targets() {
        let outer_name = name(&[b"outer", b"example"]);
        let inner_name = name(&[b"inner", b"example"]);
        let mut encoder = Encoder::new();
        encoder
            .write_rdata(|encoder| {
                encoder.write_name(&outer_name)?;
                assert!(
                    encoder
                        .write_rdata(|encoder| {
                            encoder.write_name(&inner_name)?;
                            Err(WireError::InvalidRData {
                                record_type: "test",
                                detail: "rollback",
                            })
                        })
                        .is_err()
                );
                encoder.write_name(&outer_name)?;
                encoder.write_name(&inner_name)
            })
            .unwrap();

        let mut reference = Encoder::new();
        reference
            .write_rdata(|encoder| {
                encoder.write_name(&outer_name)?;
                encoder.write_name(&outer_name)?;
                encoder.write_name(&inner_name)
            })
            .unwrap();
        assert_eq!(encoder.into_bytes(), reference.into_bytes());
    }
}
