//! Protocol constants extracted from RFC 1035.
//!
//! Each constant is grouped by the RFC 1035 section that defines it, so the
//! wire-format limits and magic numbers stay in one place instead of being
//! scattered through the codec.

/// Size limits for names and labels.
///
/// RFC 1035 §2.3.4 "Size limits" and §3.1 "Name space definitions".
/// <https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4>
mod size_limits {
    /// Maximum total length of a domain name in octets, including the
    /// length octets of every label and the terminating root label.
    pub const MAX_NAME_OCTETS: usize = 255;

    /// Maximum length of a single label in octets.
    pub const MAX_LABEL_OCTETS: u8 = 63;
}

/// `<character-string>` wire format.
///
/// RFC 1035 §3.3 "Standard RRs".
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.3>
/// Maximum valid DNS TTL after RFC 2181 §8 clarified the RFC 1035 field.
pub const MAX_TTL: u32 = i32::MAX as u32;

pub mod character_string {
    /// Maximum payload length of a `<character-string>` in octets.
    ///
    /// A `<character-string>` is a one-octet length followed by that many
    /// octets, so the payload is capped at `u8::MAX`.
    pub const MAX_OCTETS: usize = u8::MAX as usize;
}

/// DNS message header layout.
///
/// RFC 1035 §4.1.1 "Header section format".
/// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1>
pub mod header {
    /// Fixed size of the header: six 16-bit fields.
    pub const HEADER_OCTETS: usize = 12;

    /// Mask for the 4-bit OPCODE field.
    pub const OPCODE_MASK: u16 = 0x000f;
    /// Bit shift of the OPCODE field within the flags word.
    pub const OPCODE_SHIFT: u8 = 11;

    /// Mask for the one header bit that remains reserved after RFC 4035
    /// allocated the AD and CD bits.
    pub const Z_MASK: u16 = 0x0040;
    /// Bit shift of the remaining Z bit within the flags word.
    pub const Z_SHIFT: u8 = 6;

    /// Mask for the 4-bit RCODE field.
    pub const RCODE_MASK: u16 = 0x000f;

    // Single-bit flag masks within the flags word.
    /// Query/Response bit: 0 for a query, 1 for a response.
    pub const QR_FLAG: u16 = 1u16 << 15;
    /// Authoritative Answer bit.
    pub const AA_FLAG: u16 = 1u16 << 10;
    /// TrunCation bit.
    pub const TC_FLAG: u16 = 1u16 << 9;
    /// Recursion Desired bit.
    pub const RD_FLAG: u16 = 1u16 << 8;
    /// Recursion Available bit.
    pub const RA_FLAG: u16 = 1u16 << 7;
    /// Authentic Data bit (RFC 4035).
    pub const AD_FLAG: u16 = 1u16 << 5;
    /// Checking Disabled bit (RFC 4035).
    pub const CD_FLAG: u16 = 1u16 << 4;
}

/// Domain-name label types and message compression.
///
/// RFC 1035 §4.1.4 "Message compression".
/// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4>
pub mod compression {
    /// Mask selecting the top two bits of a length octet, which distinguish a
    /// normal label from a compression pointer.
    pub const LABEL_TYPE_MASK: u8 = 0xc0;

    /// The top two bits (`11`) that identify a compression pointer.
    pub const POINTER_TYPE: u8 = 0xc0;

    /// Mask selecting the low six bits of a pointer's first octet, which carry
    /// the high six bits of the 14-bit offset.
    pub const POINTER_OFFSET_MASK: u8 = 0x3f;

    /// Number of octets a compression pointer occupies on the wire.
    pub const POINTER_OCTETS: usize = 2;
}

// Re-export the size limits at the crate-root path that callers already use.
pub use size_limits::{MAX_LABEL_OCTETS, MAX_NAME_OCTETS};
