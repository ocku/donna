use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use dns::{DomainName, Message, Question, RData};
use tracing::debug;

use crate::{ResolutionCacheSource, response::normalize_response_rrsets};

use super::super::ResolutionStatsContext;

pub(in crate::resolver) enum ResponseAction {
    ContinueRound,
    RestartRound,
    Complete {
        reply: Message,
        cache_source: Option<ResolutionCacheSource>,
    },
}

pub(in crate::resolver) fn has_minimum_response_structure(
    reply: &Message,
    active_question: &Question,
) -> bool {
    let mut reply = reply.clone();
    let mut edns = match reply.edns() {
        Ok(edns) => edns,
        Err(_) => return false,
    };
    if let Some(edns) = &mut edns {
        edns.remove_extended_dns_errors();
    }
    for record in &mut reply.additionals {
        if let RData::OPT(options) = &mut record.rdata {
            options.retain(|option| !option.is_extended_dns_error());
        }
    }
    if edns
        .as_ref()
        .is_some_and(|edns| edns.version != dns::Edns::VERSION || edns.validate_options().is_err())
    {
        return false;
    }
    normalize_response_rrsets(&mut reply, active_question)
        && crate::response::cname_restart(&reply.answers, active_question).is_ok()
}

pub(in crate::resolver) struct ResponseContext<'a> {
    pub(in crate::resolver) original_question: &'a Question,
    pub(in crate::resolver) resolving_ns_hosts: &'a [DomainName],
    pub(in crate::resolver) remaining_steps: Arc<AtomicUsize>,
    pub(in crate::resolver) server: SocketAddr,
    pub(in crate::resolver) id: u16,
    pub(in crate::resolver) elapsed: Duration,
    pub(in crate::resolver) protocol: Option<transport::TransportProtocol>,
    pub(in crate::resolver) responsive_protocols: Vec<Option<transport::TransportProtocol>>,
    pub(in crate::resolver) stats: ResolutionStatsContext,
}

pub(super) fn sanitize_response_edns(reply: &mut Message, server: SocketAddr) -> bool {
    // Validate EDNS before reading its extended RCODE or allowing RRSet
    // normalization to remove an invalidly placed or duplicate OPT. A
    // malformed OPT must not make an extended error look like NOERROR.
    let mut edns = match reply.edns() {
        Ok(edns) => edns,
        Err(error) => {
            debug!(%server, ?error, "discarding DNS response with malformed EDNS metadata");
            return false;
        }
    };
    if let Some(edns) = &mut edns {
        // RFC 8914 section 6 makes EDE strictly diagnostic: its content
        // MUST NOT alter ordinary DNS protocol processing. A malformed
        // EDE remains inspectable at the transport/protocol boundary, but
        // the iterative resolver consumes (and does not forward) EDE, so
        // remove it before validating options that can affect processing.
        edns.remove_extended_dns_errors();
    }
    for record in &mut reply.additionals {
        if let RData::OPT(options) = &mut record.rdata {
            options.retain(|option| !option.is_extended_dns_error());
        }
    }
    if let Some(edns) = &edns
        && let Err(error) = edns.validate_options()
    {
        debug!(%server, ?error, "discarding DNS response with malformed EDNS options");
        return false;
    }
    if let Some(edns) = &edns
        && edns.version != dns::Edns::VERSION
    {
        debug!(
            %server,
            version = edns.version,
            "discarding DNS response with unsupported EDNS version"
        );
        return false;
    }
    true
}
