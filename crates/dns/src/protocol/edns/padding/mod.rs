mod policy;

pub use policy::{
    PaddingOutcome, PaddingPolicyError, RECOMMENDED_QUERY_PADDING_BLOCK_SIZE,
    RECOMMENDED_RESPONSE_PADDING_BLOCK_SIZE,
};

use super::{Edns, EdnsOption};

/// EDNS option code assigned to Padding by RFC 7830.
pub const EDNS_PADDING_OPTION_CODE: u16 = 12;

impl EdnsOption {
    /// Creates an RFC 7830 Padding option filled with zero octets.
    ///
    /// Zero is the recommended padding value. A zero-length option is valid
    /// and can be used by a responder when no larger padded response fits the
    /// requestor's advertised payload limit.
    #[must_use]
    pub fn padding(length: u16) -> Self {
        Self {
            code: EDNS_PADDING_OPTION_CODE,
            data: vec![0; usize::from(length)],
        }
    }

    /// Creates an RFC 7830 Padding option with caller-selected octets.
    ///
    /// Receivers must accept every octet value. Senders should normally use
    /// [`EdnsOption::padding`], but RFC 7830 permits other values where
    /// all-zero padding could be compressed before encryption.
    #[must_use]
    pub fn padding_with_data(data: Vec<u8>) -> Self {
        Self {
            code: EDNS_PADDING_OPTION_CODE,
            data,
        }
    }

    /// Returns the padding octets when this is an RFC 7830 Padding option.
    #[must_use]
    pub fn as_padding(&self) -> Option<&[u8]> {
        (self.code == EDNS_PADDING_OPTION_CODE).then_some(self.data.as_slice())
    }

    /// Returns whether this is an RFC 7830 Padding option.
    #[must_use]
    pub const fn is_padding(&self) -> bool {
        self.code == EDNS_PADDING_OPTION_CODE
    }
}

impl Edns {
    /// Returns the Padding option's octets, if present.
    ///
    /// Strict message validation rejects more than one Padding option in an
    /// OPT record, as required by RFC 7830 section 3.
    #[must_use]
    pub fn padding(&self) -> Option<&[u8]> {
        self.options.iter().find_map(EdnsOption::as_padding)
    }

    /// Replaces any Padding option with zero-filled padding at the end of the
    /// option list.
    ///
    /// The caller remains responsible for choosing a length that keeps a
    /// padded message within the requestor's advertised UDP payload size and
    /// for using padding only on an encrypted DNS transport.
    pub fn set_padding(&mut self, length: u16) {
        self.remove_padding();
        self.options.push(EdnsOption::padding(length));
    }

    /// Replaces any Padding option with caller-selected padding octets at the
    /// end of the option list.
    ///
    /// RFC 7830 recommends all-zero padding but requires receivers to accept
    /// arbitrary values. The caller remains responsible for transport
    /// confidentiality and for the requestor's UDP payload-size ceiling.
    pub fn set_padding_data(&mut self, data: Vec<u8>) {
        self.remove_padding();
        self.options.push(EdnsOption::padding_with_data(data));
    }

    /// Removes every Padding option and reports whether one was present.
    pub fn remove_padding(&mut self) -> bool {
        let old_length = self.options.len();
        self.options.retain(|option| !option.is_padding());
        self.options.len() != old_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FromWire, IntoWire, Message, MessageValidationError, RecordValidationError};

    #[test]
    fn constructs_recommended_zero_filled_padding_including_zero_length() {
        for length in [0, 1, 255, 1024] {
            let option = EdnsOption::padding(length);
            assert_eq!(option.code, EDNS_PADDING_OPTION_CODE);
            assert_eq!(option.data, vec![0; usize::from(length)]);
            assert_eq!(option.as_padding(), Some(option.data.as_slice()));
        }
    }

    #[test]
    fn accepts_and_exposes_every_inbound_padding_octet_value() {
        let data: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        let option = EdnsOption::padding_with_data(data.clone());
        assert_eq!(option.as_padding(), Some(data.as_slice()));

        let unknown = EdnsOption { code: 65000, data };
        assert_eq!(unknown.as_padding(), None);
    }

    #[test]
    fn replacing_padding_preserves_other_options_and_places_padding_last() {
        let first = EdnsOption {
            code: 1,
            data: vec![1],
        };
        let second = EdnsOption {
            code: 2,
            data: vec![2],
        };
        let mut edns = Edns {
            options: vec![
                EdnsOption::padding_with_data(vec![0xff]),
                first.clone(),
                EdnsOption::padding(3),
                second.clone(),
            ],
            ..Edns::default()
        };

        edns.set_padding(2);

        assert_eq!(edns.options, vec![first, second, EdnsOption::padding(2)]);
        assert_eq!(edns.padding(), Some([0, 0].as_slice()));
        assert!(edns.remove_padding());
        assert_eq!(edns.padding(), None);
        assert!(!edns.remove_padding());
    }

    #[test]
    fn padding_code_length_and_arbitrary_octets_round_trip_on_the_wire() {
        let padding = vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];
        let mut edns = Edns::new(1232);
        edns.set_padding_data(padding.clone());
        let message = Message::builder()
            .additionals([edns.into_record()])
            .build()
            .unwrap();

        let wire = message.into_wire().unwrap();
        assert_eq!(
            &wire[wire.len() - padding.len() - 4..wire.len() - padding.len()],
            &[0x00, 0x0c, 0x00, padding.len() as u8]
        );
        assert_eq!(&wire[wire.len() - padding.len()..], padding.as_slice());

        let decoded = Message::from_wire(&wire).unwrap();
        assert_eq!(
            decoded.edns().unwrap().unwrap().padding(),
            Some(padding.as_slice())
        );
    }

    #[test]
    fn zero_length_padding_round_trips_as_an_option_not_an_absence() {
        let mut edns = Edns::new(512);
        edns.set_padding(0);
        let message = Message::builder()
            .additionals([edns.into_record()])
            .build()
            .unwrap();

        let wire = message.into_wire().unwrap();
        assert!(wire.ends_with(&[0x00, 0x0c, 0x00, 0x00]));
        let decoded = Message::from_wire(&wire).unwrap();
        assert_eq!(
            decoded.edns().unwrap().unwrap().padding(),
            Some([].as_slice())
        );
    }

    #[test]
    fn strict_validation_rejects_more_than_one_padding_option() {
        let mut edns = Edns::new(1232);
        edns.options = vec![EdnsOption::padding(0), EdnsOption::padding(1)];

        assert_eq!(
            edns.validate_options(),
            Err(RecordValidationError::DuplicateEdnsPadding)
        );
        assert!(matches!(
            Message::builder().additionals([edns.into_record()]).build(),
            Err(MessageValidationError::InvalidRecord {
                error: RecordValidationError::DuplicateEdnsPadding,
                ..
            })
        ));
    }

    #[test]
    fn receiver_accepts_nonfinal_padding_but_outbound_validation_rejects_it() {
        let mut edns = Edns::new(1232);
        edns.options = vec![
            EdnsOption::padding(0),
            EdnsOption {
                code: 65_000,
                data: vec![1],
            },
        ];

        assert_eq!(edns.validate_options(), Ok(()));
        assert!(edns.clone().into_record().validate_received().is_ok());
        assert!(matches!(
            Message::builder().additionals([edns.into_record()]).build(),
            Err(MessageValidationError::InvalidRecord {
                error: RecordValidationError::EdnsPaddingNotLast,
                ..
            })
        ));
    }
}
