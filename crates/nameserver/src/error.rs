use std::fmt;

/// Reports invalid authoritative zone data.
#[derive(Debug)]
pub struct ZoneError(String);

impl ZoneError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ZoneError {}
