use std::time::{SystemTime, UNIX_EPOCH};

use dns::{
    IntoWire, Message, RCode, RData, RecordType, TsigAuthenticationError, TsigErrorCode, TsigKey,
    TsigRequestAuthentication, VerifiedTsigMessage, append_unsigned_tsig_error,
    tsig_time_from_unix_duration,
};

use crate::response::error_response;

pub(super) enum RequestAuthentication {
    Unsigned(Message),
    Rejected(Message),
    Authenticated {
        query: Message,
        key: TsigKey,
        request_mac: Vec<u8>,
        original_id: u16,
        fudge: u16,
        time_signed: u64,
    },
}

pub(super) fn unix_time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| tsig_time_from_unix_duration(duration).ok())
        .unwrap_or(0)
}

pub(super) fn authenticate(
    query: Message,
    wire: &[u8],
    keys: &[TsigKey],
    now: u64,
) -> RequestAuthentication {
    let Some(request_record) = query
        .additionals
        .last()
        .filter(|record| record.rtype == RecordType::TSIG)
        .cloned()
    else {
        return RequestAuthentication::Unsigned(query);
    };
    let RData::TSIG(request_tsig) = &request_record.rdata else {
        return RequestAuthentication::Rejected(error_response(&query, RCode::FormatError));
    };
    let Some(key) = keys
        .iter()
        .find(|key| key.name().eq_dns(&request_record.name))
        .cloned()
    else {
        return RequestAuthentication::Rejected(unsigned_error(
            &query,
            &request_record,
            now,
            TsigErrorCode::BadKey,
        ));
    };
    if !request_tsig.algorithm.eq_dns(&key.algorithm().name()) {
        return RequestAuthentication::Rejected(unsigned_error(
            &query,
            &request_record,
            now,
            TsigErrorCode::BadKey,
        ));
    }

    match key.authenticate_request(wire, now) {
        Ok(TsigRequestAuthentication::Verified(verified)) => authenticated(verified, key),
        Ok(TsigRequestAuthentication::BadTime(verified)) => {
            let mut response = error_response(&verified.message, RCode::NotAuthoritative);
            let server_time = now.to_be_bytes()[2..].to_vec();
            if key
                .sign_response(
                    &mut response,
                    &verified.mac,
                    verified.tsig.original_id,
                    verified.tsig.time_signed,
                    verified.tsig.fudge,
                    TsigErrorCode::BadTime,
                    server_time,
                    Some(verified.mac.len()),
                )
                .is_err()
            {
                return RequestAuthentication::Rejected(error_response(
                    &verified.message,
                    RCode::ServerFailure,
                ));
            }
            RequestAuthentication::Rejected(response)
        }
        Ok(TsigRequestAuthentication::BadTruncation(verified)) => {
            let mut response = error_response(&verified.message, RCode::NotAuthoritative);
            if key
                .sign_response(
                    &mut response,
                    &verified.mac,
                    verified.tsig.original_id,
                    now,
                    verified.tsig.fudge,
                    TsigErrorCode::BadTruncation,
                    Vec::new(),
                    None,
                )
                .is_err()
            {
                return RequestAuthentication::Rejected(error_response(
                    &verified.message,
                    RCode::ServerFailure,
                ));
            }
            RequestAuthentication::Rejected(response)
        }
        Err(TsigAuthenticationError::BadSignature) => RequestAuthentication::Rejected(
            unsigned_error(&query, &request_record, now, TsigErrorCode::BadSignature),
        ),
        Err(TsigAuthenticationError::BadKey | TsigAuthenticationError::BadAlgorithm) => {
            RequestAuthentication::Rejected(unsigned_error(
                &query,
                &request_record,
                now,
                TsigErrorCode::BadKey,
            ))
        }
        Err(_) => RequestAuthentication::Rejected(error_response(&query, RCode::FormatError)),
    }
}

fn authenticated(verified: VerifiedTsigMessage, key: TsigKey) -> RequestAuthentication {
    RequestAuthentication::Authenticated {
        query: verified.message,
        key,
        request_mac: verified.mac,
        original_id: verified.tsig.original_id,
        fudge: verified.tsig.fudge,
        time_signed: verified.tsig.time_signed,
    }
}

fn unsigned_error(
    query: &Message,
    request_record: &dns::ResourceRecord,
    now: u64,
    error: TsigErrorCode,
) -> Message {
    let mut response = error_response(query, RCode::NotAuthoritative);
    let _ = append_unsigned_tsig_error(&mut response, request_record, now, error);
    response
}

pub(super) fn sign_response(
    key: &TsigKey,
    request_mac: &[u8],
    original_id: u16,
    fudge: u16,
    response: &mut Message,
    query: &Message,
    protocol: transport::TransportProtocol,
) -> Result<(), TsigAuthenticationError> {
    key.sign_response(
        response,
        request_mac,
        original_id,
        unix_time_now(),
        fudge,
        TsigErrorCode::NoError,
        Vec::new(),
        Some(request_mac.len()),
    )?;
    if protocol == transport::TransportProtocol::Udp {
        let limit = query
            .edns()
            .ok()
            .flatten()
            .map_or(usize::from(dns::Edns::MIN_UDP_PAYLOAD_SIZE), |edns| {
                usize::from(edns.effective_udp_payload_size())
            })
            .min(usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE));
        let oversized = response
            .clone()
            .into_wire()
            .map_or(true, |wire| wire.len() > limit);
        if oversized {
            let mut truncated = super::signed_response::truncated(query, response);
            key.sign_response(
                &mut truncated,
                request_mac,
                original_id,
                unix_time_now(),
                fudge,
                TsigErrorCode::NoError,
                Vec::new(),
                Some(request_mac.len()),
            )?;
            *response = truncated;
        }
    }
    Ok(())
}

pub(super) fn signed_badtime_response(
    query: &Message,
    key: &TsigKey,
    request_mac: &[u8],
    original_id: u16,
    request_time: u64,
    fudge: u16,
    now: u64,
) -> Result<Message, TsigAuthenticationError> {
    let mut response = error_response(query, RCode::NotAuthoritative);
    key.sign_response(
        &mut response,
        request_mac,
        original_id,
        request_time,
        fudge,
        TsigErrorCode::BadTime,
        now.to_be_bytes()[2..].to_vec(),
        Some(request_mac.len()),
    )?;
    Ok(response)
}
