use smallvec::SmallVec;

use crate::wire::{Result, WireError};

/// Bounds-checked reader over a DNS message.
#[derive(Debug)]
pub(crate) struct Decoder<'a> {
    message: &'a [u8],
    position: usize,
    limit: usize,
    allow_compression: bool,
    cache_names: bool,
    // Physical label offsets arrive in increasing wire order. Each validated
    // suffix shares literal-label nodes with the rest of its name.
    name_offsets: SmallVec<[(usize, NameSuffix); 16]>,
    name_labels: SmallVec<[NameLabel<'a>; 16]>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NameSuffix {
    first: Option<usize>,
}

#[derive(Debug)]
struct NameLabel<'a> {
    bytes: &'a [u8],
    next: Option<usize>,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(message: &'a [u8]) -> Self {
        Self {
            message,
            position: 0,
            limit: message.len(),
            allow_compression: true,
            cache_names: true,
            name_offsets: SmallVec::new(),
            name_labels: SmallVec::new(),
        }
    }

    /// Reads standalone RDATA, where DNS message compression is unavailable.
    pub(crate) fn new_uncompressed(message: &'a [u8]) -> Self {
        Self {
            allow_compression: false,
            ..Self::new(message)
        }
    }

    pub(crate) fn allows_compression(&self) -> bool {
        self.allow_compression
    }

    /// A message containing one question and no records has no subsequent
    /// name that could reference that question. Pointer validation within the
    /// question still runs normally; only unused suffix indexing is skipped.
    pub(crate) fn omit_name_cache(&mut self) {
        self.cache_names = false;
    }

    pub(crate) fn caches_names(&self) -> bool {
        self.cache_names
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }
    pub(crate) fn remaining(&self) -> usize {
        self.limit - self.position
    }
    pub(crate) fn message(&self) -> &'a [u8] {
        self.message
    }
    pub(crate) fn cached_name(&self, offset: usize) -> Option<NameSuffix> {
        let index = self
            .name_offsets
            .binary_search_by_key(&offset, |&(offset, _)| offset)
            .ok()?;
        Some(self.name_offsets[index].1)
    }

    pub(crate) fn append_cached_name(&self, suffix: NameSuffix, labels: &mut Vec<Vec<u8>>) {
        let mut current = suffix.first;
        while let Some(index) = current {
            let label = &self.name_labels[index];
            labels.push(label.bytes.to_vec());
            current = label.next;
        }
    }

    pub(crate) fn cache_name(&mut self, offsets: &[usize], terminal: NameSuffix) {
        let Some((&last, literal_offsets)) = offsets.split_last() else {
            return;
        };
        let first_index = self.name_labels.len();
        for (index, &offset) in literal_offsets.iter().enumerate() {
            let length = usize::from(self.message[offset]);
            let next = if index + 1 < literal_offsets.len() {
                Some(first_index + index + 1)
            } else {
                terminal.first
            };
            self.name_labels.push(NameLabel {
                bytes: &self.message[offset + 1..offset + 1 + length],
                next,
            });
            self.name_offsets.push((
                offset,
                NameSuffix {
                    first: Some(first_index + index),
                },
            ));
        }
        self.name_offsets.push((last, terminal));
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }
    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }
    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }
    pub(crate) fn read_u48(&mut self) -> Result<u64> {
        Ok(self
            .read_array::<6>()?
            .into_iter()
            .fold(0_u64, |value, octet| (value << 8) | u64::from(octet)))
    }

    pub(crate) fn read_exact(&mut self, length: usize) -> Result<&'a [u8]> {
        self.require(length)?;
        let start = self.position;
        self.position += length;
        Ok(&self.message[start..self.position])
    }

    pub(crate) fn with_limit<T>(
        &mut self,
        length: usize,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.require(length)?;
        let previous_limit = self.limit;
        let end = self.position + length;
        self.limit = end;
        let value = f(self);
        let consumed_all = self.position == end;
        self.limit = previous_limit;
        match value {
            Ok(value) if consumed_all => Ok(value),
            Ok(_) => Err(WireError::InvalidRData {
                record_type: "resource record",
                detail: "RDATA length was not consumed exactly",
            }),
            Err(error) => Err(error),
        }
    }

    fn require(&self, length: usize) -> Result<()> {
        if length > self.remaining() {
            return Err(WireError::Truncated {
                position: self.position,
                needed: length,
                remaining: self.remaining(),
            });
        }
        Ok(())
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_exact(N)?;
        Ok(bytes.try_into().expect("slice length is checked"))
    }
}
