use smallvec::SmallVec;

use crate::constants::compression::{
    LABEL_TYPE_MASK, POINTER_OCTETS, POINTER_OFFSET_MASK, POINTER_TYPE,
};
use crate::protocol::DomainName;
use crate::wire::{Decoder, FromWire, IntoWire, Result, WireError, decode_complete};

pub(crate) fn decode_uncompressed_name(
    decoder: &mut Decoder<'_>,
    record_type: &'static str,
    detail: &'static str,
) -> Result<DomainName> {
    let message = decoder.message();
    let mut cursor = decoder.position();
    let limit = cursor + decoder.remaining();

    loop {
        let Some(&first) = message.get(cursor).filter(|_| cursor < limit) else {
            return Err(WireError::Truncated {
                position: cursor,
                needed: 1,
                remaining: limit.saturating_sub(cursor),
            });
        };
        match first & LABEL_TYPE_MASK {
            0x00 => {
                let length = usize::from(first);
                let needed = length + 1;
                if cursor + needed > limit {
                    return Err(WireError::Truncated {
                        position: cursor,
                        needed,
                        remaining: limit - cursor,
                    });
                }
                cursor += needed;
                if length == 0 {
                    break;
                }
            }
            POINTER_TYPE => {
                return Err(WireError::InvalidRData {
                    record_type,
                    detail,
                });
            }
            value => {
                return Err(WireError::InvalidLabelType {
                    position: cursor,
                    value,
                });
            }
        }
    }

    decode_name(decoder)
}

pub(crate) fn decode_name(decoder: &mut Decoder<'_>) -> Result<DomainName> {
    let message = decoder.message();
    let mut cursor = decoder.position();
    let pointer_limit = cursor;
    let mut terminal = super::decoder::NameSuffix::default();
    let mut labels = Vec::new();

    let mut direct_offsets = SmallVec::<[usize; 16]>::new();

    loop {
        let limit = decoder.position() + decoder.remaining();
        if cursor >= limit {
            return Err(WireError::Truncated {
                position: cursor,
                needed: 1,
                remaining: limit.saturating_sub(cursor),
            });
        }
        let first = message[cursor];
        // Publish targets only after the complete name has been validated.
        if decoder.caches_names() {
            direct_offsets.push(cursor);
        }
        match first & LABEL_TYPE_MASK {
            0x00 => {
                let length = usize::from(first);
                let end = cursor + 1 + length;
                if end > limit {
                    return Err(WireError::Truncated {
                        position: cursor,
                        needed: length + 1,
                        remaining: limit - cursor,
                    });
                }
                cursor = end;
                decoder.read_exact(length + 1)?;
                if length == 0 {
                    break;
                }
                labels.push(message[end - length..end].to_vec());
            }
            POINTER_TYPE => {
                if !decoder.allows_compression() {
                    return Err(WireError::InvalidRData {
                        record_type: "standalone RDATA",
                        detail: "compression pointers are forbidden",
                    });
                }
                let end = cursor + POINTER_OCTETS;
                if end > limit {
                    return Err(WireError::Truncated {
                        position: cursor,
                        needed: POINTER_OCTETS,
                        remaining: limit - cursor,
                    });
                }
                let offset = (usize::from(first & POINTER_OFFSET_MASK) << 8)
                    | usize::from(message[cursor + 1]);
                if offset >= message.len() {
                    return Err(WireError::CompressionPointerOutOfBounds {
                        position: cursor,
                        offset,
                    });
                }
                if offset >= cursor {
                    return Err(WireError::CompressionPointerForward {
                        position: cursor,
                        offset,
                    });
                }
                // A pointer into the name currently being decoded would form
                // a cycle. Earlier complete names have validated suffix links,
                // so a pointer chain never requires reparsing wire octets.
                if offset >= pointer_limit {
                    return Err(WireError::CompressionPointerCycle {
                        position: cursor,
                        offset,
                    });
                }
                let Some(suffix) = decoder.cached_name(offset) else {
                    return Err(WireError::CompressionPointerInvalidTarget {
                        position: cursor,
                        offset,
                    });
                };
                decoder.read_exact(POINTER_OCTETS)?;
                decoder.append_cached_name(suffix, &mut labels);
                terminal = suffix;
                break;
            }
            value => {
                return Err(WireError::InvalidLabelType {
                    position: cursor,
                    value,
                });
            }
        }
    }

    let name = DomainName::from_labels(labels).map_err(|_| WireError::InvalidRData {
        record_type: "domain name",
        detail: "expanded name exceeds RFC 1035 limits",
    })?;
    decoder.cache_name(&direct_offsets, terminal);
    Ok(name)
}

impl IntoWire for DomainName {
    fn into_wire(&self) -> Result<Vec<u8>> {
        let mut encoder = crate::wire::Encoder::new();
        encoder.write_name(self)?;
        Ok(encoder.into_bytes())
    }
}

impl FromWire for DomainName {
    fn from_wire(bytes: &[u8]) -> Result<Self> {
        decode_complete(bytes, decode_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_question_without_suffix_index_keeps_exact_decode_results() {
        fn decode(packet: &[u8], omit_cache: bool) -> crate::wire::Result<(DomainName, u16, u16)> {
            let mut decoder = Decoder::new(packet);
            decoder.read_exact(12)?;
            if omit_cache {
                decoder.omit_name_cache();
            }
            let question = crate::wire::decode_question(&mut decoder)?;
            if decoder.remaining() != 0 {
                return Err(WireError::InvalidValue {
                    field: "message trailing octets",
                    value: decoder.remaining() as u64,
                });
            }
            Ok((
                question.qname,
                question.qtype.value(),
                question.qclass.value(),
            ))
        }
        for labels in [
            Vec::new(),
            vec![b"www".to_vec(), vec![0, 0xff, b'A']],
            vec![
                vec![b'a'; 63],
                vec![b'b'; 63],
                vec![b'c'; 63],
                vec![b'd'; 61],
            ],
            vec![vec![b'a']; 127],
        ] {
            let question = crate::Question {
                qname: DomainName::from_labels(labels).unwrap(),
                qtype: crate::QueryType::A,
                qclass: crate::QClassType::Class(crate::ClassType::IN),
            };
            let mut packet = vec![0; 12];
            packet.extend_from_slice(&question.into_wire().unwrap());
            for end in 12..=packet.len() {
                assert_eq!(decode(&packet[..end], false), decode(&packet[..end], true));
            }
            for index in 12..packet.len() {
                let original = packet[index];
                for value in [0, 0x3f, 0x40, 0x80, 0xc0, 0xff] {
                    packet[index] = value;
                    assert_eq!(decode(&packet, false), decode(&packet, true));
                }
                packet[index] = original;
            }
        }
    }

    #[test]
    fn accepts_rfc1035_name_length_boundaries() {
        let labels = vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 61],
        ];
        let name = DomainName::from_labels(labels.clone()).unwrap();
        let wire = name.into_wire().unwrap();

        assert_eq!(wire.len(), 255);
        assert_eq!(DomainName::from_wire(&wire).unwrap().as_ref(), labels);
        assert_eq!(DomainName::from_wire(&[0]).unwrap(), DomainName::root());
    }

    #[test]
    fn rejects_reserved_and_truncated_label_encodings() {
        for wire in [
            &[0x40, 0][..],
            &[0x80, 0][..],
            &[3, b'a', b'b'][..],
            &[0xc0][..],
        ] {
            assert!(DomainName::from_wire(wire).is_err(), "accepted {wire:?}");
        }
    }

    #[test]
    fn decodes_a_literal_prefix_followed_by_a_backward_pointer() {
        let wire = [3, b'c', b'o', b'm', 0, 3, b'w', b'w', b'w', 0xc0, 0];
        let mut decoder = Decoder::new(&wire);
        assert_eq!(
            decode_name(&mut decoder).unwrap().as_ref(),
            &[b"com".to_vec()]
        );
        assert_eq!(
            decode_name(&mut decoder).unwrap().as_ref(),
            &[b"www".to_vec(), b"com".to_vec()]
        );
    }

    #[test]
    fn decodes_pointer_only_suffix_root_and_pointer_targets() {
        let wire = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, // www.example.com, suffix offset 4, root offset 16
            0xc0, 4, // pointer-only example.com at offset 17
            0xc0, 16, // pointer-only root
            0xc0, 17, // pointer to the prior pointer
        ];
        let mut decoder = Decoder::new(&wire);

        assert_eq!(
            decode_name(&mut decoder).unwrap().as_ref(),
            &[b"www".to_vec(), b"example".to_vec(), b"com".to_vec()]
        );
        assert_eq!(
            decode_name(&mut decoder).unwrap().as_ref(),
            &[b"example".to_vec(), b"com".to_vec()]
        );
        assert_eq!(decode_name(&mut decoder).unwrap(), DomainName::root());
        assert_eq!(
            decode_name(&mut decoder).unwrap().as_ref(),
            &[b"example".to_vec(), b"com".to_vec()]
        );
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn rejects_literal_prefix_pointer_to_current_name_start() {
        let wire = [0, 1, b'a', 0xc0, 1];
        let mut decoder = Decoder::new(&wire);
        assert_eq!(decode_name(&mut decoder).unwrap(), DomainName::root());
        assert!(matches!(
            decode_name(&mut decoder),
            Err(WireError::CompressionPointerCycle {
                position: 3,
                offset: 1
            })
        ));
    }

    #[test]
    fn rejects_minimal_backward_compression_cycle() {
        let wire = [0, 1, b'a', 1, b'b', 0xc0, 3];
        let mut decoder = Decoder::new(&wire);
        assert_eq!(decode_name(&mut decoder).unwrap(), DomainName::root());
        assert!(matches!(
            decode_name(&mut decoder),
            Err(WireError::CompressionPointerCycle {
                position: 5,
                offset: 3
            })
        ));
    }

    #[test]
    fn rejects_out_of_bounds_compression_pointers() {
        let wire = [0xc0, 0xff];
        let mut decoder = Decoder::new(&wire);
        assert!(matches!(
            decode_name(&mut decoder),
            Err(WireError::CompressionPointerOutOfBounds {
                position: 0,
                offset: 255
            })
        ));
    }

    #[test]
    fn decodes_backward_pointer_chains() {
        let mut wire = vec![0];
        let chain_length = 1024;
        let mut previous_offset = 0usize;
        for _ in 0..chain_length {
            let pointer = 0xc000 | u16::try_from(previous_offset).unwrap();
            previous_offset = wire.len();
            wire.extend_from_slice(&pointer.to_be_bytes());
        }

        let mut decoder = Decoder::new(&wire);
        for _ in 0..=chain_length {
            assert_eq!(decode_name(&mut decoder).unwrap(), DomainName::root());
        }
    }

    #[test]
    fn rejects_compressed_names_expanding_past_255_octets() {
        let mut wire = Vec::new();
        for byte in *b"abcd" {
            wire.push(63);
            wire.extend(std::iter::repeat_n(byte, 63));
        }
        wire.push(0);
        let pointer_position = wire.len();
        wire.extend_from_slice(&[1, b'x', 0xc0, 0]);

        let mut decoder = Decoder::new(&wire);
        assert!(decode_name(&mut decoder).is_err());
        assert_eq!(decoder.position(), pointer_position);
        assert!(decode_name(&mut decoder).is_err());
    }

    #[test]
    fn decodes_every_suffix_of_a_maximum_label_count_name_and_its_aliases() {
        let mut wire = Vec::new();
        for index in 0..127 {
            wire.extend_from_slice(&[1, b'A' + index % 26]);
        }
        wire.push(0);
        let mut expected = Vec::new();
        for index in 0..=127 {
            expected.push(
                (index..127)
                    .map(|index| vec![b'A' + index % 26])
                    .collect::<Vec<_>>(),
            );
            let pointer = 0xc000 | (index as u16 * 2);
            wire.extend_from_slice(&pointer.to_be_bytes());
        }
        let aliases_start = 255;
        for index in 0..=127 {
            let pointer = 0xc000 | (aliases_start + index as u16 * 2);
            wire.extend_from_slice(&pointer.to_be_bytes());
        }

        let mut decoder = Decoder::new(&wire);
        assert_eq!(decode_name(&mut decoder).unwrap().wire_len(), 255);
        for suffixes in [&expected, &expected] {
            for labels in suffixes {
                assert_eq!(decode_name(&mut decoder).unwrap().as_ref(), labels);
            }
        }
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn rejects_pointer_into_label_payload_after_valid_name() {
        let wire = [3, 1, b'a', 0, 0, 0xc0, 1];
        let mut decoder = Decoder::new(&wire);
        assert_eq!(
            decode_name(&mut decoder).unwrap().as_ref(),
            &[vec![1, b'a', 0]]
        );
        assert!(matches!(
            decode_name(&mut decoder),
            Err(WireError::CompressionPointerInvalidTarget {
                position: 5,
                offset: 1
            })
        ));
    }
}
