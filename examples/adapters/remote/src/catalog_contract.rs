//! PostgreSQL catalog publication, malformed storage and recovery checks.

use crate::{engine_fixture::Failure, postgres_zones::PostgresZones};
use dns::{IntoWire, Message, RCode};
use nameserver::{NameServer, ZoneStore};

pub async fn check(authority: &NameServer, request: &Message, url: &str) -> Result<(), Failure> {
    let zones = PostgresZones::new(url.to_owned());
    let catalog = zones.snapshot().await?;
    assert_eq!(catalog.zones().count(), 3);
    let replacement: Vec<_> = catalog.zones().cloned().collect();
    let (first, second) = tokio::join!(
        zones.compare_exchange(catalog.revision(), &replacement),
        zones.compare_exchange(catalog.revision(), &replacement)
    );
    assert_ne!(first?, second?, "exactly one catalog writer must commit");
    assert!(
        !zones
            .compare_exchange(catalog.revision(), &replacement)
            .await?
    );
    let original_response = authority.handle(request.clone()).await;
    assert_eq!(original_response.headers.rcode, RCode::Ok);
    assert!(!original_response.answers.is_empty());
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let row = client
        .query_one("SELECT payload FROM donna_catalog WHERE singleton", &[])
        .await?;
    let original: Vec<u8> = row.try_get(0)?;
    let mut trailing = original.clone();
    trailing.push(0);
    let malformed = [
        Vec::new(),
        vec![0, 0, 1, 1], // More than the allowed number of zones.
        original[..original.len() - 1].to_vec(),
        trailing,
    ];
    for payload in malformed {
        client
            .execute(
                "UPDATE donna_catalog SET revision = revision + 1, payload = $1 WHERE singleton",
                &[&payload],
            )
            .await?;
        assert!(
            zones.snapshot().await.is_err(),
            "malformed catalog accepted"
        );
        assert_eq!(
            authority.handle(request.clone()).await.headers.rcode,
            RCode::ServerFailure,
            "an invalid catalog must not serve a stale or partial answer"
        );
    }
    client
        .execute(
            "UPDATE donna_catalog SET revision = revision + 1, payload = $1 WHERE singleton",
            &[&original],
        )
        .await?;
    let restored = authority.handle(request.clone()).await;
    assert_eq!(restored.headers.rcode, RCode::Ok);
    assert_eq!(restored.into_wire()?, original_response.into_wire()?);
    println!("PASS corrupt PostgreSQL catalogs: fail closed and recover");
    Ok(())
}
