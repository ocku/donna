use crate::{DomainName, FromWire, IntoWire, Message, RData, wire::WireError};

fn question(additional: u16) -> Vec<u8> {
    let mut wire: Vec<u8> = [0x1234_u16, 0x8000, 1, 0, 0, additional]
        .into_iter()
        .flat_map(u16::to_be_bytes)
        .collect();
    wire.extend_from_slice(b"\x05MiXeD\x07example\x04test\0\0\x01\0\x01");
    wire
}

fn record(owner: &[u8], kind: u16, data: &[u8]) -> Vec<u8> {
    let mut wire = owner.to_vec();
    wire.extend_from_slice(&kind.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&30_u32.to_be_bytes());
    wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
    wire.extend_from_slice(data);
    wire
}

#[test]
fn pointers_target_only_complete_prior_names_across_question_and_rdata() {
    let mut base = question(2);
    assert_eq!(base.len(), 36);
    // PTR owner reuses the question; its RDATA reuses a question suffix.
    base.extend_from_slice(&record(&[0xc0, 12], 12, &[0xc0, 18]));
    assert_eq!(base.len(), 50);
    let legal = [12, 18, 26, 31, 36, 48];
    for target in 0..52 {
        let mut wire = base.clone();
        wire.extend_from_slice(&record(
            &(0xc000 | target as u16).to_be_bytes(),
            12,
            &[0xc0, 12],
        ));
        let decoded = Message::from_wire(&wire);
        assert_eq!(decoded.is_ok(), legal.contains(&target), "target {target}");
        if let Ok(message) = decoded {
            let expected = match target {
                12 | 36 => "MiXeD.example.test.",
                18 | 48 => "example.test.",
                26 => "test.",
                31 => ".",
                _ => unreachable!(),
            };
            assert_eq!(
                message.additionals[1].name.as_ref(),
                DomainName::from_dotted(expected).unwrap().as_ref()
            );
            assert!(matches!(&message.additionals[1].rdata, RData::PTR(name)
                if name.as_ref() == message.questions[0].qname.as_ref()));
            let round_trip = Message::from_wire(&message.into_wire().unwrap()).unwrap();
            assert_eq!(
                round_trip.additionals[1].name.as_ref(),
                message.additionals[1].name.as_ref()
            );
        }
    }
}

#[test]
fn compression_targets_at_the_fourteen_bit_boundary_still_require_name_boundaries() {
    for boundary in [16382, 16383] {
        let mut wire = question(3);
        let padding = boundary - wire.len() - 12;
        wire.extend_from_slice(&record(&[0xc0, 12], 65000, &vec![0; padding]));
        assert_eq!(wire.len(), boundary);
        wire.extend_from_slice(&record(b"\x03far\0", 1, &[192, 0, 2, 1]));
        let mut valid = wire.clone();
        valid.extend_from_slice(&record(
            &(0xc000 | boundary as u16).to_be_bytes(),
            28,
            &[0; 16],
        ));
        let message = Message::from_wire(&valid).unwrap();
        assert_eq!(message.additionals[2].name.as_ref(), &[b"far".to_vec()]);
        for target in [boundary - 1, boundary + 1] {
            let mut invalid = wire.clone();
            invalid.extend_from_slice(&record(
                &(0xc000 | target as u16).to_be_bytes(),
                28,
                &[0; 16],
            ));
            assert!(matches!(
                Message::from_wire(&invalid),
                Err(WireError::CompressionPointerInvalidTarget { .. })
            ));
        }
    }
}

#[test]
fn malformed_name_syntax_precedes_complete_expanded_length_validation() {
    let mut prefix = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for _ in 0..5 {
        prefix.push(63);
        prefix.extend_from_slice(&[b'x'; 63]);
    }
    assert_eq!(prefix.len(), 332);
    for (tail, expected) in [
        (
            vec![0x40],
            WireError::InvalidLabelType {
                position: 332,
                value: 0x40,
            },
        ),
        (
            vec![0xc0],
            WireError::Truncated {
                position: 332,
                needed: 2,
                remaining: 1,
            },
        ),
        (
            vec![0xc0, 0],
            WireError::CompressionPointerInvalidTarget {
                position: 332,
                offset: 0,
            },
        ),
        (
            vec![63, 1, 2],
            WireError::Truncated {
                position: 332,
                needed: 64,
                remaining: 3,
            },
        ),
    ] {
        let mut wire = prefix.clone();
        wire.extend_from_slice(&tail);
        assert_eq!(
            Message::from_wire(&wire).unwrap_err().to_string(),
            expected.to_string()
        );
    }
    prefix.push(0);
    assert!(matches!(
        Message::from_wire(&prefix),
        Err(WireError::InvalidRData {
            record_type: "domain name",
            ..
        })
    ));
}
