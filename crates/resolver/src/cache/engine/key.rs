use std::io;

/// Every persistent DNS cache role, including validation and failure state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum CacheCategory {
    /// Positive answers and authenticated DNAME material.
    Positive = 1,
    /// NXDOMAIN and NODATA proof bundles.
    Negative = 2,
    /// Nameserver addresses and refresh leases.
    Delegation = 3,
    /// Repeated DNSSEC validation failures.
    Bad = 4,
    /// Scoped terminal failures and backoff history.
    Failure = 5,
    /// Genuinely authenticated DNSKEY sets and chain bounds.
    AuthenticatedKeys = 6,
}
/// Complete entry-family predicate, including its class and cache category.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheEntryFamily {
    /// Cache role; different roles still share the atomic namespace generation.
    pub category: CacheCategory,
    /// Lowercase literal DNS wire name, including the final root byte.
    pub owner: Vec<u8>,
    /// DNS class code.
    pub class: u16,
}
/// A canonical per-entry identity. This metadata confers no authentication.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheEntryKey {
    /// Category, canonical owner and class.
    pub family: CacheEntryFamily,
    /// Core-defined variant: type/negative-kind/CD/anchor as applicable.
    pub discriminator: Vec<u8>,
}
impl CacheEntryKey {
    /// Stable binary key for provider indexes. Rejects oversized or malformed
    /// metadata; providers may store these bytes without understanding DNS RDATA.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        use dns::{DomainName, FromWire, IntoWire};
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid cache entry key");
        if self.family.owner.len() > 255 || self.discriminator.len() > 512 {
            return Err(bad());
        }
        let name = DomainName::from_wire(&self.family.owner).map_err(|_| bad())?;
        if name.into_wire().map_err(|_| bad())? != self.family.owner
            || self.family.owner.iter().any(u8::is_ascii_uppercase)
        {
            return Err(bad());
        }
        let mut out = vec![self.family.category as u8];
        out.extend_from_slice(&self.family.class.to_be_bytes());
        out.push(self.family.owner.len() as u8);
        out.extend_from_slice(&self.family.owner);
        out.extend_from_slice(&(self.discriminator.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.discriminator);
        Ok(out)
    }
    /// Decodes provider-stored index metadata without trusting its contents.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid cache entry key");
        let category = match bytes.first() {
            Some(1) => CacheCategory::Positive,
            Some(2) => CacheCategory::Negative,
            Some(3) => CacheCategory::Delegation,
            Some(4) => CacheCategory::Bad,
            Some(5) => CacheCategory::Failure,
            Some(6) => CacheCategory::AuthenticatedKeys,
            _ => return Err(bad()),
        };
        let class = u16::from_be_bytes(
            bytes
                .get(1..3)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?,
        );
        let n = usize::from(*bytes.get(3).ok_or_else(bad)?);
        let owner = bytes.get(4..4 + n).ok_or_else(bad)?.to_vec();
        let m = u16::from_be_bytes(
            bytes
                .get(4 + n..6 + n)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?,
        ) as usize;
        if m > 512 {
            return Err(bad());
        }
        let discriminator = bytes
            .get(6 + n..)
            .filter(|x| x.len() == m)
            .ok_or_else(bad)?
            .to_vec();
        let key = Self {
            family: CacheEntryFamily {
                category,
                owner,
                class,
            },
            discriminator,
        };
        if key.encode()? != bytes {
            return Err(bad());
        }
        Ok(key)
    }
}
