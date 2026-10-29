/// DNSSEC KEY RDATA used by SIG and SIG(0).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    /// KEY flags describing key ownership and permitted use.
    pub flags: u16,
    /// Protocol value; RFC 2931 normally uses 3 (DNSSEC) or 255 (all).
    pub protocol: u8,
    /// DNSSEC algorithm number.
    pub algorithm: u8,
    /// Algorithm-specific public-key octets.
    pub public_key: Vec<u8>,
}

impl Key {
    /// Computes the RFC 2535 key tag, including the RSA/MD5 modulus rule.
    pub fn key_tag(&self) -> u16 {
        // RFC 2535 §4.1.6 uses the next-to-last two modulus octets for
        // RSA/MD5; Appendix C's checksum applies to the other algorithms.
        if self.algorithm == 1 && self.public_key.len() >= 3 {
            let length = self.public_key.len();
            return u16::from_be_bytes([self.public_key[length - 3], self.public_key[length - 2]]);
        }
        let mut bytes = Vec::with_capacity(4 + self.public_key.len());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.push(self.protocol);
        bytes.push(self.algorithm);
        bytes.extend_from_slice(&self.public_key);
        let mut accumulator = 0_u32;
        for (index, octet) in bytes.iter().copied().enumerate() {
            accumulator += if index & 1 == 0 {
                u32::from(octet) << 8
            } else {
                u32::from(octet)
            };
        }
        accumulator += (accumulator >> 16) & 0xffff;
        accumulator as u16
    }
}

#[cfg(test)]
mod tests {
    use super::Key;

    #[test]
    fn rsa_md5_key_tag_uses_modulus_octets_instead_of_checksum() {
        let key = Key {
            flags: 0x0100,
            protocol: 3,
            algorithm: 1,
            public_key: vec![1, 3, 0x80, 0x12, 0x34, 0x56],
        };
        assert_eq!(key.key_tag(), 0x1234);
        assert_eq!(
            Key {
                algorithm: 3,
                ..key
            }
            .key_tag(),
            0xb96e
        );
    }
}
