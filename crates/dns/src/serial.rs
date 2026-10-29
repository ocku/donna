use std::cmp::Ordering;
use std::fmt;

/// A 32-bit DNS SOA serial number using RFC 1982 arithmetic.
///
/// Serial numbers wrap at `2^32`. Their ordering is relative rather than a
/// conventional total order: values exactly `2^31` apart have no defined
/// ordering.
///
/// RFC 1982: <https://www.rfc-editor.org/rfc/rfc1982>
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SerialNumber(u32);

impl SerialNumber {
    /// Largest increment for which RFC 1982 addition is defined.
    pub const MAX_INCREMENT: u32 = (1 << 31) - 1;

    const HALF_SPACE: u32 = 1 << 31;

    /// Creates a serial number from its 32-bit representation.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the serial number's 32-bit representation.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Adds an RFC 1982 increment, wrapping in the 32-bit serial space.
    ///
    /// Returns `None` when `increment` exceeds [`Self::MAX_INCREMENT`], for
    /// which RFC 1982 leaves addition undefined.
    pub const fn checked_add(self, increment: u32) -> Option<Self> {
        if increment <= Self::MAX_INCREMENT {
            Some(Self(self.0.wrapping_add(increment)))
        } else {
            None
        }
    }

    /// Compares two serial numbers according to RFC 1982.
    ///
    /// Returns `None` when the serials are exactly half the sequence space
    /// (`2^31`) apart, because RFC 1982 leaves both orderings undefined.
    ///
    /// This operation is deliberately not exposed through [`PartialOrd`]: the
    /// circular RFC 1982 relation is not transitive across the whole sequence
    /// space and therefore does not satisfy that trait's contract.
    pub const fn compare(self, other: Self) -> Option<Ordering> {
        if self.0 == other.0 {
            return Some(Ordering::Equal);
        }

        match other.0.wrapping_sub(self.0) {
            Self::HALF_SPACE => None,
            distance if distance < Self::HALF_SPACE => Some(Ordering::Less),
            _ => Some(Ordering::Greater),
        }
    }
}

impl From<u32> for SerialNumber {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<SerialNumber> for u32 {
    fn from(serial: SerialNumber) -> Self {
        serial.value()
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addition_wraps_in_the_32_bit_serial_space() {
        assert_eq!(
            SerialNumber::new(u32::MAX).checked_add(1),
            Some(SerialNumber::new(0))
        );
        assert_eq!(
            SerialNumber::new(2_147_483_650).checked_add(SerialNumber::MAX_INCREMENT),
            Some(SerialNumber::new(1))
        );
    }

    #[test]
    fn addition_accepts_only_the_rfc1982_increment_range() {
        let serial = SerialNumber::new(42);

        assert_eq!(serial.checked_add(0), Some(serial));
        assert!(serial.checked_add(SerialNumber::MAX_INCREMENT).is_some());
        assert_eq!(serial.checked_add(1 << 31), None);
        assert_eq!(serial.checked_add(u32::MAX), None);
    }

    #[test]
    fn comparison_handles_equal_and_ordinary_values() {
        let serial = SerialNumber::new(100);

        assert_eq!(serial.compare(serial), Some(Ordering::Equal));
        assert_eq!(serial.compare(SerialNumber::new(101)), Some(Ordering::Less));
        assert_eq!(
            SerialNumber::new(101).compare(serial),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn comparison_follows_values_across_the_wrap_point() {
        assert_eq!(
            SerialNumber::new(u32::MAX).compare(SerialNumber::new(0)),
            Some(Ordering::Less)
        );
        assert_eq!(
            SerialNumber::new(0).compare(SerialNumber::new(u32::MAX)),
            Some(Ordering::Greater)
        );
        assert_eq!(
            SerialNumber::new(100).compare(SerialNumber::new(u32::MAX)),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn comparison_is_undefined_exactly_half_a_space_apart() {
        for (left, right) in [
            (0, 1 << 31),
            (1, (1 << 31) + 1),
            (u32::MAX, i32::MAX as u32),
        ] {
            assert_eq!(
                SerialNumber::new(left).compare(SerialNumber::new(right)),
                None
            );
            assert_eq!(
                SerialNumber::new(right).compare(SerialNumber::new(left)),
                None
            );
        }
    }
}
