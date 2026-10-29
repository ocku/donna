//! Per-entry seals reuse record codecs, never native indexes or full snapshots.
use crate::{
    CacheEngineConfig, CacheEntryKey, SealedCacheEntry,
    cache::codec::{CapturedEntry, Reader, Writer, invalid, unix_nanos},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{io, time::Instant};

const MAGIC: &[u8; 8] = b"DNENTRY1";
const AUTH_TAG_BYTES: usize = 32;
const MIN_SEALED_ENTRY_BYTES: usize = 64;
pub(super) const ENTRY_METADATA_BYTES: usize = size_of::<i128>() + size_of::<u64>();

#[derive(Clone, Copy)]
pub(super) struct TimeBase {
    pub instant: Instant,
    pub wall: i128,
}

impl TimeBase {
    pub fn now() -> io::Result<Self> {
        let wall = unix_nanos()?;
        Ok(Self {
            wall,
            instant: Instant::now(),
        })
    }
}

pub(super) struct OpenEntry {
    pub key: CacheEntryKey,
    pub body: Vec<u8>,
    pub links: Vec<dns::ResourceRecord>,
}

fn mac(
    config: &CacheEngineConfig,
    binding: &[u8],
    namespace: &[u8],
    entry: &SealedCacheEntry,
    payload: &[u8],
) -> io::Result<Hmac<Sha256>> {
    let mut m = Hmac::<Sha256>::new_from_slice(&config.secret).map_err(|_| invalid())?;
    m.update(b"donna per-entry cache v1\0");
    m.update(&(namespace.len() as u64).to_be_bytes());
    m.update(namespace);
    m.update(binding);
    let key = entry.key.encode()?;
    m.update(&(key.len() as u64).to_be_bytes());
    m.update(&key);
    m.update(&entry.expires_unix_nanos.to_be_bytes());
    m.update(&entry.weight.to_be_bytes());
    m.update(payload);
    Ok(m)
}

pub(super) fn writer<'a>(
    config: &'a CacheEngineConfig,
    binding: &'a [u8],
    time: TimeBase,
) -> io::Result<Writer<'a>> {
    let mut out = Writer::new(config.maximum_bytes, &config.secret, binding)?;
    out.instant = time.instant;
    out.wall = time.wall;
    Ok(out)
}

pub(super) fn reader<'a>(
    bytes: &'a [u8],
    config: &'a CacheEngineConfig,
    binding: &'a [u8],
    time: TimeBase,
) -> io::Result<Reader<'a>> {
    let mut input = Reader::new(bytes, &config.secret, binding)?;
    input.instant = time.instant;
    input.wall = time.wall;
    Ok(input)
}

pub(super) fn seal(
    row: CapturedEntry,
    config: &CacheEngineConfig,
    binding: &[u8],
    namespace: &[u8],
    time: TimeBase,
) -> io::Result<SealedCacheEntry> {
    let mut out = writer(config, binding, time)?;
    out.raw(MAGIC)?;
    out.raw(&time.wall.to_be_bytes())?;
    out.records(&row.links)?;
    out.blob(&row.body)?;
    let mut entry = SealedCacheEntry {
        key: row.key,
        value: Vec::new(),
        expires_unix_nanos: row.expiry_wall,
        weight: 0,
    };
    entry.weight = u64::try_from(
        out.bytes.len() + AUTH_TAG_BYTES + entry.key.encode()?.len() + ENTRY_METADATA_BYTES,
    )
    .map_err(|_| invalid())?;
    let tag = mac(config, binding, namespace, &entry, &out.bytes)?
        .finalize()
        .into_bytes();
    out.bytes.extend_from_slice(&tag);
    entry.value = out.bytes;
    Ok(entry)
}

pub(super) fn open(
    entry: &SealedCacheEntry,
    config: &CacheEngineConfig,
    binding: &[u8],
    namespace: &[u8],
    time: TimeBase,
) -> io::Result<OpenEntry> {
    if entry.value.len() < MIN_SEALED_ENTRY_BYTES || entry.value.len() > config.maximum_bytes {
        return Err(invalid());
    }
    let weight =
        u64::try_from(entry.value.len() + entry.key.encode()?.len() + ENTRY_METADATA_BYTES)
            .map_err(|_| invalid())?;
    if entry.weight != weight {
        return Err(invalid());
    }
    let (payload, tag) = entry.value.split_at(entry.value.len() - AUTH_TAG_BYTES);
    mac(config, binding, namespace, entry, payload)?
        .verify_slice(tag)
        .map_err(|_| invalid())?;
    let mut input = reader(payload, config, binding, time)?;
    if input.raw(MAGIC.len())? != MAGIC {
        return Err(invalid());
    }
    let issued = i128::from_be_bytes(
        input
            .raw(size_of::<i128>())?
            .try_into()
            .map_err(|_| invalid())?,
    );
    if issued > unix_nanos()? {
        return Err(invalid());
    }
    let links = input.records()?;
    if links
        .iter()
        .any(|x| !matches!(x.rtype, dns::RecordType::CNAME | dns::RecordType::DNAME))
    {
        return Err(invalid());
    }
    let body = input.blob(config.maximum_bytes)?.to_vec();
    if !input.finished() {
        return Err(invalid());
    }
    Ok(OpenEntry {
        key: entry.key.clone(),
        body,
        links,
    })
}
