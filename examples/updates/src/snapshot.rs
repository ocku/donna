//! Small, durable wire snapshots for the UPDATE interoperability example.

use std::{fs, io::Write, path::PathBuf};

use dns::{FromWire, Headers, IntoWire, Message, master::MasterFile};
use nameserver::{UpdatePersistence, UpdatePersistenceError, Zone};

#[derive(Debug)]
pub struct Snapshot(pub PathBuf);

impl Snapshot {
    pub fn load(&self) -> Result<Option<MasterFile>, UpdatePersistenceError> {
        let bytes = match fs::read(&self.0) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(MasterFile {
            records: Message::from_wire(&bytes)?.answers,
        }))
    }
}

impl UpdatePersistence for Snapshot {
    fn persist<'future>(
        &'future self,
        zone: &'future Zone,
    ) -> transport::BoxFuture<'future, Result<(), UpdatePersistenceError>> {
        Box::pin(async move {
            // This deliberately small example stores at most one DNS message's
            // worth of records. Encoding fails before publication if it exceeds
            // that bound; production storage should use a scalable snapshot format.
            let bytes = Message::builder()
                .headers(Headers {
                    qr: true,
                    ..Headers::default()
                })
                .answers(zone.records().iter().cloned())
                .build()?
                .into_wire()?;
            let path = self.0.clone();
            tokio::task::spawn_blocking(move || -> Result<(), UpdatePersistenceError> {
                let temporary = path.with_extension("pending");
                let mut file = fs::File::create(&temporary)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                fs::rename(temporary, &path)?;
                let directory = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."));
                fs::File::open(directory)?.sync_all()?;
                Ok(())
            })
            .await??;
            Ok(())
        })
    }
}
