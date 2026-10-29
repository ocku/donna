//! Independent first-target dictionary oracle for complete emitted wire bytes.
use super::*;
use std::collections::HashMap;

#[derive(Default)]
struct Original {
    bytes: Vec<u8>,
    targets: HashMap<Vec<u8>, u16>,
}

impl Original {
    fn name(&mut self, name: &DomainName, compressed: bool) {
        let labels = name.as_ref();
        let mut packed = Vec::new();
        for label in labels {
            packed.push(label.len() as u8);
            packed.extend_from_slice(label);
        }
        packed.push(0);
        let mut start = 0;
        for label in labels {
            let suffix = &packed[start..];
            if compressed && let Some(&target) = self.targets.get(suffix) {
                self.bytes
                    .extend_from_slice(&(0xc000 | target).to_be_bytes());
                return;
            }
            if self.bytes.len() < 16384 {
                self.targets
                    .entry(suffix.to_vec())
                    .or_insert(self.bytes.len() as u16);
            }
            self.bytes.push(label.len() as u8);
            self.bytes.extend_from_slice(label);
            start += label.len() + 1;
        }
        self.bytes.push(0);
    }
}

#[test]
fn lookup_and_registration_match_original_bytes_through_promotion_and_pointer_boundary() {
    let mut names = vec![DomainName::root()];
    for labels in [
        vec![b"www".to_vec(), b"Example".to_vec(), b"test".to_vec()],
        vec![b"x".to_vec(), b"Example".to_vec(), b"test".to_vec()],
        vec![b"x".to_vec(), b"example".to_vec(), b"test".to_vec()],
        vec![vec![0, 255, b'A'], b"Example".to_vec(), b"test".to_vec()],
        vec![vec![b'a']; 127],
        vec![vec![b'a']; 126],
        vec![b"*".to_vec(), b"Example".to_vec(), b"test".to_vec()],
    ] {
        names.push(DomainName::from_labels(labels).unwrap());
    }
    // More than sixteen distinct suffixes exercise dictionary promotion. The
    // differing owner lengths also cross the inline key-storage byte bound.
    for index in 0..40 {
        names.push(
            DomainName::from_labels(vec![
                vec![index; usize::from(index % 63) + 1],
                b"Example".to_vec(),
                b"test".to_vec(),
            ])
            .unwrap(),
        );
    }
    for padding in [0, 16350, 16383, 16384, 16400] {
        let mut encoder = Encoder::new();
        let mut original = Original::default();
        encoder.write_exact(&vec![0; padding]);
        original.bytes.resize(padding, 0);
        for (index, name) in names.iter().cycle().take(names.len() * 3).enumerate() {
            let compressed = index % 7 != 0;
            if compressed {
                encoder.write_name(name).unwrap();
            } else {
                encoder.write_uncompressed_name(name);
            }
            original.name(name, compressed);
            assert_eq!(
                encoder.bytes, original.bytes,
                "padding={padding} step={index}"
            );
        }
        let added =
            DomainName::from_labels(vec![b"rollback-only".to_vec(), b"test".to_vec()]).unwrap();
        let checkpoint = original.bytes.len();
        let result = encoder.write_rdata(|encoder| {
            encoder.write_name(&added)?;
            Err(WireError::LengthOverflow {
                field: "oracle",
                length: 1,
                maximum: 0,
            })
        });
        assert!(result.is_err());
        // Model the preexisting rollback independently, including dictionary
        // targets that were registered inside the discarded RDATA length field.
        original.bytes.extend_from_slice(&[0, 0]);
        original.name(&added, true);
        original.bytes.truncate(checkpoint);
        original
            .targets
            .retain(|_, target| usize::from(*target) < checkpoint);
        encoder.write_name(&added).unwrap();
        original.name(&added, true);
        assert_eq!(encoder.bytes, original.bytes, "rollback padding={padding}");
    }
}

fn literal(name: &DomainName) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.as_ref() {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0);
    wire
}

fn edge_names() -> Vec<DomainName> {
    let mut names = vec![DomainName::root()];
    for labels in [
        vec![b"a".to_vec()],
        vec![b"a".to_vec(), b"b".to_vec()],
        vec![b"WwW".to_vec(), b"Example".to_vec(), b"TEST".to_vec()],
        vec![vec![0, 0xc0, 0xff, b'A'], b"Example".to_vec()],
        vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 61],
        ],
        vec![vec![b'a']; 127],
        vec![b"*".to_vec(), b"Example".to_vec(), b"TEST".to_vec()],
    ] {
        names.push(DomainName::from_labels(labels).unwrap());
    }
    for index in 0..40_u8 {
        names.push(
            DomainName::from_labels(vec![
                vec![index; usize::from(index % 63) + 1],
                b"Example".to_vec(),
                b"TEST".to_vec(),
            ])
            .unwrap(),
        );
    }
    names
}

#[test]
fn bulk_literal_and_compressed_names_keep_exact_targets_and_round_trip() {
    let names = edge_names();
    for padding in [0, 16300, 16382, 16383, 16384, 16400] {
        for pattern in 0..3 {
            let mut encoder = Encoder::with_capacity(1);
            encoder.write_exact(&vec![0; padding]);
            let mut original = Original::default();
            original.bytes.resize(padding, 0);
            let mut sequence = Vec::new();
            for (index, name) in names.iter().cycle().take(names.len() * 2).enumerate() {
                let compressed = match pattern {
                    0 => false,
                    1 => index % 2 == 0,
                    _ => true,
                };
                let start = encoder.position();
                if compressed {
                    encoder.write_name(name).unwrap();
                } else {
                    encoder.write_uncompressed_name(name);
                    assert_eq!(&encoder.bytes[start..], literal(name));
                }
                original.name(name, compressed);
                assert_eq!(
                    encoder.bytes, original.bytes,
                    "padding={padding} step={index}"
                );
                sequence.push(name);
            }
            // The strict decoder permits pointers only to earlier validated
            // label boundaries; this also rejects any future/bogus target.
            let mut decoder = crate::wire::Decoder::new(&encoder.bytes);
            decoder.read_exact(padding).unwrap();
            for expected in sequence {
                let decoded = crate::wire::decode_name(&mut decoder).unwrap();
                assert_eq!(decoded.as_ref(), expected.as_ref());
            }
            assert_eq!(decoder.remaining(), 0);
        }
    }
}

#[test]
fn bulk_registration_rolls_back_literal_suffixes_after_failure_and_overflow() {
    for promoted in [false, true] {
        for padding in [0, 16380, 16383, 16384] {
            for overflow in [false, true] {
                let mut encoder = Encoder::new();
                let mut original = Original::default();
                encoder.write_exact(&vec![0; padding]);
                original.bytes.resize(padding, 0);
                let names = edge_names();
                let count = if promoted { names.len() } else { 4 };
                for name in &names[..count] {
                    encoder.write_uncompressed_name(name);
                    original.name(name, false);
                }
                let added = DomainName::from_labels(vec![
                    b"discarded-only".to_vec(),
                    b"unregistered-parent".to_vec(),
                ])
                .unwrap();
                let checkpoint = encoder.position();
                let result = encoder.write_rdata(|encoder| {
                    encoder.write_uncompressed_name(&added);
                    encoder.write_name(&names[3])?;
                    if overflow {
                        encoder.write_exact(&vec![0; usize::from(u16::MAX) + 1]);
                        Ok(())
                    } else {
                        Err(WireError::InvalidRData {
                            record_type: "test",
                            detail: "discard all newly registered literal suffixes",
                        })
                    }
                });
                assert!(result.is_err());
                assert_eq!(encoder.position(), checkpoint);
                assert_eq!(encoder.bytes, original.bytes);
                for name in [&added, &names[3], &added, &names[count - 1]] {
                    encoder.write_name(name).unwrap();
                    original.name(name, true);
                }
                assert_eq!(encoder.bytes, original.bytes);
            }
        }
    }
}

#[test]
fn rrsig_signer_stays_literal_and_registers_later_valid_pointer_targets() {
    for signer in [
        DomainName::root(),
        DomainName::from_dotted("SiGnEr.Example.TEST.").unwrap(),
        DomainName::from_labels(vec![vec![0, 0xc0, 255], b"Example".to_vec()]).unwrap(),
        DomainName::from_labels(vec![vec![b'a']; 127]).unwrap(),
    ] {
        for already_registered in [false, true] {
            let prior = if already_registered {
                signer.clone()
            } else {
                DomainName::from_dotted("unrelated.").unwrap()
            };
            let mut encoder = Encoder::with_capacity(1);
            encoder.write_name(&prior).unwrap();
            let rdata_start = encoder.position();
            let signature = vec![0xaa; 64];
            let rrsig = crate::RData::RRSIG(crate::Rrsig {
                type_covered: 1,
                algorithm: 8,
                labels: 3,
                original_ttl: 60,
                signature_expiration: 3000,
                signature_inception: 1000,
                key_tag: 1,
                signer_name: signer.clone(),
                signature: signature.clone(),
            });
            crate::wire::encode_rdata(&rrsig, &mut encoder).unwrap();
            let signer_start = rdata_start + 18;
            // RFC 4034 section 3.1.7 forbids compression in this field,
            // including when a matching name has already been emitted.
            assert_eq!(
                &encoder.bytes[signer_start..signer_start + signer.wire_len()],
                literal(&signer)
            );
            let repeated_start = encoder.position();
            encoder.write_name(&signer).unwrap();
            if !signer.as_ref().is_empty() {
                let target = if already_registered { 0 } else { signer_start };
                assert_eq!(
                    &encoder.bytes[repeated_start..],
                    (0xc000 | target as u16).to_be_bytes()
                );
            }
            let mut decoder = crate::wire::Decoder::new(&encoder.bytes);
            let decoded_prior = crate::wire::decode_name(&mut decoder).unwrap();
            assert_eq!(decoded_prior.as_ref(), prior.as_ref());
            decoder.read_exact(18).unwrap();
            let decoded_signer = crate::wire::decode_uncompressed_name(
                &mut decoder,
                "RRSIG",
                "compressed signer is forbidden",
            )
            .unwrap();
            assert_eq!(decoded_signer.as_ref(), signer.as_ref());
            decoder.read_exact(signature.len()).unwrap();
            let decoded_later = crate::wire::decode_name(&mut decoder).unwrap();
            assert_eq!(decoded_later.as_ref(), signer.as_ref());
            assert_eq!(decoder.remaining(), 0);
        }
    }
}

#[test]
fn nsec_next_name_is_literal_even_after_a_matching_compression_target() {
    for next in edge_names().into_iter().take(8) {
        let mut encoder = Encoder::with_capacity(1);
        encoder.write_name(&next).unwrap();
        let start = encoder.position();
        crate::wire::encode_rdata(
            &crate::RData::NSEC(crate::Nsec {
                next_domain_name: next.clone(),
                type_bitmap: crate::TypeBitmap::new([1, 46, 47]).unwrap(),
            }),
            &mut encoder,
        )
        .unwrap();
        // RFC 4034 section 4.1.1 prohibits Next Domain Name compression.
        assert_eq!(
            &encoder.bytes[start..start + next.wire_len()],
            literal(&next)
        );
        let bitmap_bytes = encoder.position() - start - next.wire_len();
        encoder.write_name(&next).unwrap();
        let mut decoder = crate::wire::Decoder::new(&encoder.bytes);
        assert_eq!(
            crate::wire::decode_name(&mut decoder).unwrap().as_ref(),
            next.as_ref()
        );
        let decoded = crate::wire::decode_uncompressed_name(
            &mut decoder,
            "NSEC",
            "compressed next name is forbidden",
        )
        .unwrap();
        assert_eq!(decoded.as_ref(), next.as_ref());
        decoder.read_exact(bitmap_bytes).unwrap();
        assert_eq!(
            crate::wire::decode_name(&mut decoder).unwrap().as_ref(),
            next.as_ref()
        );
        assert_eq!(decoder.remaining(), 0);
    }
}
