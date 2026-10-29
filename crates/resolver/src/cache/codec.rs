//! Bounded internal cache codecs. Storage never chooses DNS policy.
use dns::{DomainName, FromWire, IntoWire, Question, ResourceRecord};
use std::{
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid resolver cache entry")
}

pub(crate) fn unix_nanos() -> io::Result<i128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_nanos() as i128)
}

pub(crate) fn question_from_codes(name: &[u8], qtype: u16, qclass: u16) -> io::Result<Question> {
    if name.len() > 255 {
        return Err(invalid());
    }
    let mut bytes = name.to_vec();
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&qclass.to_be_bytes());
    Question::from_wire(&bytes).map_err(|_| invalid())
}

pub(crate) struct CapturedEntry {
    pub(crate) key: crate::CacheEntryKey,
    pub(crate) expiry_wall: i128,
    pub(crate) links: Vec<ResourceRecord>,
    pub(crate) body: Vec<u8>,
}
struct CaptureStart {
    key: crate::CacheEntryKey,
    expiry_wall: i128,
    links: Vec<ResourceRecord>,
    start: usize,
}

pub(crate) struct Writer<'a> {
    pub(crate) secret: &'a [u8; 32],
    pub(crate) binding: &'a [u8],
    pub(crate) bytes: Vec<u8>,
    maximum: usize,
    captures: Option<Vec<CapturedEntry>>,
    capture_start: Option<CaptureStart>,
    pub(crate) instant: Instant,
    pub(crate) wall: i128,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(maximum: usize, secret: &'a [u8; 32], binding: &'a [u8]) -> io::Result<Self> {
        let wall = unix_nanos()?;
        let instant = Instant::now();
        Ok(Self {
            secret,
            binding,
            bytes: Vec::new(),
            maximum,
            captures: None,
            capture_start: None,
            instant,
            wall,
        })
    }
    pub(crate) fn capture_entries(&mut self) {
        self.captures = Some(Vec::new());
    }
    pub(crate) fn take_entries(&mut self) -> Vec<CapturedEntry> {
        self.captures.take().unwrap_or_default()
    }
    pub(crate) fn begin_entry(
        &mut self,
        entry: &impl crate::cache::store::CacheEntry,
        records: &[ResourceRecord],
    ) -> io::Result<()> {
        if self.captures.is_none() {
            return Ok(());
        }
        let key = entry.engine_key().ok_or_else(invalid)?;
        let at = entry.expires_at();
        let delta = if at >= self.instant {
            at.duration_since(self.instant).as_nanos() as i128
        } else {
            -(self.instant.duration_since(at).as_nanos() as i128)
        };
        let links = records
            .iter()
            .filter(|r| matches!(r.rtype, dns::RecordType::CNAME | dns::RecordType::DNAME))
            .cloned()
            .collect();
        self.capture_start = Some(CaptureStart {
            key,
            expiry_wall: self.wall + delta,
            links,
            start: self.bytes.len(),
        });
        Ok(())
    }
    pub(crate) fn end_entry(&mut self) -> io::Result<()> {
        if let Some(rows) = &mut self.captures {
            let start = self.capture_start.take().ok_or_else(invalid)?;
            rows.push(CapturedEntry {
                key: start.key,
                expiry_wall: start.expiry_wall,
                links: start.links,
                body: self.bytes[start.start..].to_vec(),
            });
        }
        Ok(())
    }

    pub(crate) fn raw(&mut self, value: &[u8]) -> io::Result<()> {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.maximum)
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "resolver cache entries exceed configured bound",
            ));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub(crate) fn byte(&mut self, value: u8) -> io::Result<()> {
        self.raw(&[value])
    }
    pub(crate) fn flag(&mut self, value: bool) -> io::Result<()> {
        self.byte(u8::from(value))
    }
    pub(crate) fn u32(&mut self, value: u32) -> io::Result<()> {
        self.raw(&value.to_be_bytes())
    }
    pub(crate) fn count(&mut self, value: usize) -> io::Result<()> {
        self.u32(u32::try_from(value).map_err(|_| invalid())?)
    }
    pub(crate) fn blob(&mut self, value: &[u8]) -> io::Result<()> {
        self.count(value.len())?;
        self.raw(value)
    }
    pub(crate) fn wire(&mut self, value: &impl IntoWire) -> io::Result<()> {
        self.blob(&value.into_wire().map_err(|_| invalid())?)
    }
    pub(crate) fn records(&mut self, records: &[ResourceRecord]) -> io::Result<()> {
        self.count(records.len())?;
        for record in records {
            self.wire(record)?;
        }
        Ok(())
    }
    pub(crate) fn instant(&mut self, instant: Instant) -> io::Result<()> {
        let delta = if instant >= self.instant {
            instant.duration_since(self.instant).as_nanos() as i128
        } else {
            -(self.instant.duration_since(instant).as_nanos() as i128)
        };
        self.raw(&(self.wall + delta).to_be_bytes())
    }
}

pub(crate) struct Reader<'a> {
    pub(crate) secret: &'a [u8; 32],
    pub(crate) binding: &'a [u8],
    bytes: &'a [u8],
    pub(crate) instant: Instant,
    pub(crate) wall: i128,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(
        bytes: &'a [u8],
        secret: &'a [u8; 32],
        binding: &'a [u8],
    ) -> io::Result<Self> {
        let instant = Instant::now();
        Ok(Self {
            secret,
            binding,
            bytes,
            instant,
            wall: unix_nanos()?,
        })
    }
    pub(crate) fn finished(&self) -> bool {
        self.bytes.is_empty()
    }
    pub(crate) fn raw(&mut self, length: usize) -> io::Result<&'a [u8]> {
        if length > self.bytes.len() {
            return Err(invalid());
        }
        let (value, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(value)
    }
    pub(crate) fn byte(&mut self) -> io::Result<u8> {
        Ok(self.raw(1)?[0])
    }
    pub(crate) fn flag(&mut self) -> io::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        }
    }
    pub(crate) fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(
            self.raw(4)?.try_into().map_err(|_| invalid())?,
        ))
    }
    pub(crate) fn count(&mut self, maximum: usize) -> io::Result<usize> {
        let count = self.u32()? as usize;
        // Every encoded item requires at least one octet. This check precedes
        // allocations, including counts in a successfully authenticated blob.
        if count > maximum || count > self.bytes.len() {
            return Err(invalid());
        }
        Ok(count)
    }
    pub(crate) fn blob(&mut self, maximum: usize) -> io::Result<&'a [u8]> {
        let length = self.count(maximum)?;
        self.raw(length)
    }
    pub(crate) fn items(&mut self, maximum: usize, minimum_bytes: usize) -> io::Result<usize> {
        let count = self.count(maximum)?;
        if count > self.bytes.len() / minimum_bytes {
            return Err(invalid());
        }
        Ok(count)
    }
    pub(crate) fn name(&mut self) -> io::Result<DomainName> {
        DomainName::from_wire(self.blob(255)?).map_err(|_| invalid())
    }
    pub(crate) fn question(&mut self) -> io::Result<Question> {
        Question::from_wire(self.blob(259)?).map_err(|_| invalid())
    }
    pub(crate) fn record(&mut self) -> io::Result<ResourceRecord> {
        ResourceRecord::from_wire(self.blob(65_535)?).map_err(|_| invalid())
    }
    pub(crate) fn records(&mut self) -> io::Result<Vec<ResourceRecord>> {
        let count = self.items(65_535, 15)?;
        (0..count).map(|_| self.record()).collect()
    }
    pub(crate) fn instant(&mut self) -> io::Result<Instant> {
        let absolute = i128::from_be_bytes(self.raw(16)?.try_into().map_err(|_| invalid())?);
        let delta = absolute.checked_sub(self.wall).ok_or_else(invalid)?;
        let magnitude = u64::try_from(delta.unsigned_abs()).map_err(|_| invalid())?;
        if delta >= 0 {
            self.instant.checked_add(Duration::from_nanos(magnitude))
        } else {
            self.instant.checked_sub(Duration::from_nanos(magnitude))
        }
        .ok_or_else(invalid)
    }
}
