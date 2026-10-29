//! Single-row PostgreSQL catalog: one revision and one complete bounded value.
use dns::{DomainName, FromWire, IntoWire, ResourceRecord, master::MasterFile};
use nameserver::{Zone, ZoneSnapshot, ZoneStore, ZoneStoreError};
use std::{io, sync::Arc, time::Duration};
use tokio::time::timeout;
use tokio_postgres::{Client, NoTls};

const DEADLINE: Duration = Duration::from_secs(3);
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ZONES: usize = 256;
const MAX_RECORDS: usize = 65536;

pub struct PostgresZones {
    url: String,
}
impl std::fmt::Debug for PostgresZones {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresZones").finish_non_exhaustive()
    }
}
impl PostgresZones {
    pub fn new(url: String) -> Self {
        Self { url }
    }
    async fn connect(&self) -> Result<Client, ZoneStoreError> {
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }
    pub async fn initialize(&self) -> Result<(), ZoneStoreError> {
        timeout(DEADLINE, async {
            let client = self.connect().await?;
            client
                .batch_execute(
                    "CREATE TABLE IF NOT EXISTS donna_catalog (
                singleton BOOLEAN PRIMARY KEY CHECK (singleton),
                revision BIGINT NOT NULL CHECK (revision >= 0),
                payload BYTEA NOT NULL CHECK (octet_length(payload) <= 4194304)
            ); INSERT INTO donna_catalog (singleton, revision, payload)
              VALUES (TRUE, 0, decode('00000000', 'hex')) ON CONFLICT DO NOTHING;",
                )
                .await?;
            Ok(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "PostgreSQL initialization timed out",
            )
        })?
    }
}

fn push(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ZoneStoreError> {
    let next = out
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(bytes.len()))
        .ok_or("catalog size overflow")?;
    if next > MAX_BYTES {
        return Err("catalog too large".into());
    }
    let size = u32::try_from(bytes.len())?;
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn encode(zones: &[Arc<Zone>]) -> Result<Vec<u8>, ZoneStoreError> {
    if zones.len() > MAX_ZONES {
        return Err("too many zones".into());
    }
    ZoneSnapshot::new(Vec::new(), zones.iter().cloned())?;
    let mut out = (zones.len() as u32).to_be_bytes().to_vec();
    for zone in zones {
        if zone.records().len() > MAX_RECORDS {
            return Err("too many records".into());
        }
        push(&mut out, &zone.apex().into_wire()?)?;
        out.extend_from_slice(&(zone.records().len() as u32).to_be_bytes());
        for record in zone.records() {
            push(&mut out, &record.into_wire()?)?;
        }
    }
    if out.len() > MAX_BYTES {
        return Err("catalog too large".into());
    }
    Ok(out)
}
fn number(input: &mut &[u8]) -> Result<usize, ZoneStoreError> {
    if input.len() < 4 {
        return Err("truncated catalog".into());
    }
    let (length, rest) = input.split_at(4);
    *input = rest;
    Ok(u32::from_be_bytes(length.try_into()?) as usize)
}
fn field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], ZoneStoreError> {
    let length = number(input)?;
    if length > input.len() {
        return Err("truncated catalog value".into());
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}
fn decode(mut input: &[u8]) -> Result<Vec<Arc<Zone>>, ZoneStoreError> {
    if input.len() > MAX_BYTES {
        return Err("catalog too large".into());
    }
    let count = number(&mut input)?;
    if count > MAX_ZONES {
        return Err("too many zones".into());
    }
    let mut zones = Vec::with_capacity(count);
    for _ in 0..count {
        let apex = DomainName::from_wire(field(&mut input)?)?;
        let count = number(&mut input)?;
        if count > MAX_RECORDS {
            return Err("too many records".into());
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(ResourceRecord::from_wire(field(&mut input)?)?);
        }
        zones.push(Arc::new(Zone::from_master(apex, MasterFile { records })?));
    }
    if !input.is_empty() {
        return Err("trailing catalog bytes".into());
    }
    Ok(zones)
}
impl ZoneStore for PostgresZones {
    fn snapshot<'a>(&'a self) -> transport::BoxFuture<'a, Result<ZoneSnapshot, ZoneStoreError>> {
        Box::pin(async move {
            timeout(DEADLINE, async {
                let client = self.connect().await?;
                let row = client
                    .query_opt(
                        "SELECT revision, payload FROM donna_catalog
                    WHERE singleton AND octet_length(payload) <= 4194304",
                        &[],
                    )
                    .await?
                    .ok_or("missing or oversized catalog")?;
                let revision: i64 = row.try_get(0)?;
                let data: Vec<u8> = row.try_get(1)?;
                ZoneSnapshot::new(revision.to_be_bytes().to_vec(), decode(&data)?)
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "PostgreSQL checkout timed out"))?
        })
    }
    fn compare_exchange<'a>(
        &'a self,
        expected: &'a [u8],
        zones: &'a [Arc<Zone>],
    ) -> transport::BoxFuture<'a, Result<bool, ZoneStoreError>> {
        Box::pin(async move {
            let revision = i64::from_be_bytes(expected.try_into()?);
            if revision < 0 {
                return Err("invalid revision".into());
            }
            let payload = encode(zones)?;
            timeout(DEADLINE, async {
                let client = self.connect().await?;
                let row = client
                    .query_opt(
                        "UPDATE donna_catalog SET revision = revision + 1, payload = $2
                    WHERE singleton AND revision = $1 RETURNING revision",
                        &[&revision, &payload],
                    )
                    .await?;
                Ok(row.is_some())
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PostgreSQL write timed out; it may have committed",
                )
            })?
        })
    }
}
