//! RFC 1035 authoritative standard-query processing.

#![deny(missing_docs)]

mod error;
mod name;
mod response;
mod server;
mod zone;

pub use error::ZoneError;
pub use server::{
    InstallError, InstallOutcome, NameServer, NameServerConfig, NotifyConfig, NotifyTarget,
    UpdateIdentity, UpdatePersistence, UpdatePersistenceError, UpdateRule, ZoneSnapshot, ZoneStore,
    ZoneStoreError,
};
pub use zone::Zone;
