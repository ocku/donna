//! Application wire envelope: Redis indexes do not understand DNS RDATA.
use resolver::{CacheEntryFamily, CacheEntryKey, SealedCacheEntry};
use std::io;

pub const MAX_ENTRY: usize = 1024 * 1024;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

pub fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
pub fn field(key: &CacheEntryKey) -> io::Result<String> {
    Ok(format!("e:{}", hex(&key.encode()?)))
}
pub fn family(family: &CacheEntryFamily) -> io::Result<String> {
    let key = CacheEntryKey {
        family: family.clone(),
        discriminator: Vec::new(),
    };
    Ok(format!("f:{}", hex(&key.encode()?)))
}
pub fn ancestors(family: &CacheEntryFamily) -> io::Result<Vec<String>> {
    let mut current = family.clone();
    let mut result = Vec::new();
    loop {
        result.push(self::family(&current)?);
        let length = usize::from(current.owner[0]);
        if length == 0 {
            break;
        }
        current.owner = current.owner[length + 1..].to_vec();
    }
    Ok(result)
}
pub fn encode(entry: &SealedCacheEntry) -> io::Result<Vec<u8>> {
    let key = entry.key.encode()?;
    let size = 2 + key.len() + 16 + 8 + 4 + entry.value.len();
    if size > MAX_ENTRY {
        return Err(invalid("entry exceeds adapter bound"));
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(&key);
    out.extend_from_slice(&entry.expires_unix_nanos.to_be_bytes());
    out.extend_from_slice(&entry.weight.to_be_bytes());
    out.extend_from_slice(&(entry.value.len() as u32).to_be_bytes());
    out.extend_from_slice(&entry.value);
    Ok(out)
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if input.len() < n {
        return Err(invalid("truncated provider entry"));
    }
    let (value, rest) = input.split_at(n);
    *input = rest;
    Ok(value)
}
pub fn decode(field: &[u8], mut input: &[u8]) -> io::Result<SealedCacheEntry> {
    if input.len() > MAX_ENTRY {
        return Err(invalid("entry exceeds adapter bound"));
    }
    let length = u16::from_be_bytes(take(&mut input, 2)?.try_into().unwrap()) as usize;
    let key = CacheEntryKey::decode(take(&mut input, length)?)?;
    if self::field(&key)?.as_bytes() != field {
        return Err(invalid("entry/index key mismatch"));
    }
    let expires_unix_nanos = i128::from_be_bytes(take(&mut input, 16)?.try_into().unwrap());
    let weight = u64::from_be_bytes(take(&mut input, 8)?.try_into().unwrap());
    let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
    let value = take(&mut input, length)?.to_vec();
    if !input.is_empty() {
        return Err(invalid("trailing provider entry bytes"));
    }
    Ok(SealedCacheEntry {
        key,
        value,
        expires_unix_nanos,
        weight,
    })
}
pub fn revision(bytes: &[u8]) -> bool {
    bytes.len() <= 16
        && std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n <= 9_007_199_254_740_991 && n.to_string().as_bytes() == bytes)
}
