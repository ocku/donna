use base64ct::{Base64UrlUnpadded, Encoding};
use dns::Message;
use http::Uri;
use tokio::time;

use crate::{MAX_TCP_MESSAGE_OCTETS, TransportError, has_tsig};

use super::{DohClientConfig, DohMethod, http_io_error};

pub(super) fn request_uri(
    config: &DohClientConfig,
    wire: &[u8],
) -> Result<(DohMethod, Uri), TransportError> {
    let endpoint = format!("https://{}{}", config.authority, config.path);
    if config.method == DohMethod::Get {
        let uri = format!("{endpoint}?dns={}", Base64UrlUnpadded::encode_string(wire));
        if let Ok(uri) = uri.parse() {
            return Ok((DohMethod::Get, uri));
        }
        // Base64url can grow a valid 65535-octet DNS query beyond the HTTP
        // library's URI limit. POST carries it intact at the same endpoint.
    }
    endpoint
        .parse()
        .map(|uri| (DohMethod::Post, uri))
        .map_err(|_| TransportError::InvalidHttpProtocol("configured URI is invalid"))
}

pub(super) fn prepared_query(query: &Message) -> Result<Message, TransportError> {
    let authenticated = has_tsig(query);
    let mut query = query.clone();
    if !authenticated {
        query.headers.id = 0;
    }
    if !authenticated
        && query
            .edns()
            .map_err(|_| {
                TransportError::InvalidHttpProtocol("query contains malformed EDNS metadata")
            })?
            .is_some()
    {
        crate::message::pad_query_for_encrypted_stream(&mut query)?;
    }
    Ok(query)
}

pub(super) async fn receive_body(
    body: &mut h2::RecvStream,
    deadline: time::Instant,
) -> Result<Vec<u8>, TransportError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = time::timeout_at(deadline, body.data())
        .await
        .map_err(|_| TransportError::Timeout)?
    {
        let chunk = chunk.map_err(http_io_error)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_TCP_MESSAGE_OCTETS {
            return Err(TransportError::MessageTooLong {
                length: bytes.len().saturating_add(chunk.len()),
                maximum: MAX_TCP_MESSAGE_OCTETS,
            });
        }
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(http_io_error)?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
