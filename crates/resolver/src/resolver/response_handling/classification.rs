//! Decide how far the current authority can complete an alias chain.
use super::*;
use std::net::SocketAddr;

#[derive(Default)]
pub(super) struct Classification {
    pub(super) cname: Option<(Vec<dns::ResourceRecord>, dns::DomainName)>,
    pub(super) complete_answer: bool,
    pub(super) nodata_question: Option<Question>,
    pub(super) restart: Option<(Vec<dns::ResourceRecord>, dns::DomainName, Question)>,
}

struct AliasTarget {
    records: Vec<dns::ResourceRecord>,
    name: dns::DomainName,
    question: Question,
    authoritative: bool,
}

pub(super) fn classify(
    reply: &Message,
    state: &ResolutionState<'_>,
    cname: Option<(Vec<dns::ResourceRecord>, dns::DomainName)>,
    server: SocketAddr,
) -> Result<Classification, ()> {
    // A server can authoritatively publish a CNAME whose target crosses
    // out of its zone or into a delegated child, but that does not
    // authorize a CNAME chain owned beyond that boundary. Stop at the
    // first crossing and resolve the target through its own delegation.
    let mut cname_crossed_delegation = false;
    let cname = cname.map(|(chain_records, target)| {
        if let Some(prefix) = trusted_cname_prefix(
            &chain_records,
            &state.active_question,
            &state.current_delegation_zone,
            reply,
        ) {
            cname_crossed_delegation = true;
            prefix
        } else {
            (chain_records, target)
        }
    });

    let mut result = Classification {
        cname,
        ..Classification::default()
    };
    if let Some((chain_records, target)) = result.cname.clone() {
        let target_question = Question {
            qname: target.clone(),
            ..state.active_question.clone()
        };
        // Authority stops at a child zone cut. A parent can legitimately
        // return an alias together with the referral for its canonical
        // target, but answer data owned at or below that cut belongs to
        // the child and must not be accepted or cached. DS at the exact
        // cut remains parent-side data (RFC 4035 section 2.4).
        let target_delegation =
            applicable_child_delegation(reply, &target_question, &state.current_delegation_zone);
        let target_is_authoritative =
            delegation_covers_name(&state.current_delegation_zone, &target_question.qname)
                && target_delegation.is_none();
        if reply.headers.rcode == RCode::Ok {
            if cname_crossed_delegation {
                result.restart = Some((
                    chain_records.clone(),
                    target.clone(),
                    target_question.clone(),
                ));
            }
            // RFC 1035 permits the canonical RRset to accompany its CNAME
            // chain. Test the requested type at the canonical name, not
            // the alias.
            result.complete_answer = has_requested_answer(&reply.answers, &target_question);
            if result.complete_answer && !target_is_authoritative {
                // Data at a canonical name outside the server's validated
                // delegation is not cacheable answer data. Follow the
                // CNAME and resolve that target through its own delegation.
                debug!(
                    %server,
                    target = ?target,
                    "ignoring canonical answer beyond an authority boundary and resolving target independently"
                );
                result.complete_answer = false;
                result.restart = Some((
                    chain_records.clone(),
                    target.clone(),
                    target_question.clone(),
                ));
            }
            if !result.complete_answer {
                classify_nodata(
                    reply,
                    state,
                    server,
                    AliasTarget {
                        records: chain_records,
                        name: target,
                        question: target_question,
                        authoritative: target_is_authoritative,
                    },
                    &mut result,
                )?;
            }
        } else if reply.headers.rcode == RCode::NameError
            && reply.headers.aa
            && !target_is_authoritative
        {
            if !has_only_negative_answer_metadata(&reply.answers)
                && !has_dname_negative_answer_metadata(&reply.answers, &state.active_question)
            {
                debug!(%server, "discarding DNS response with contradictory CNAME/NXDOMAIN data");
                return Err(());
            }
            debug!(
                %server,
                target = ?target,
                "ignoring CNAME/NXDOMAIN proof beyond an authority boundary and resolving target independently"
            );
            result.restart = Some((chain_records, target, target_question));
        }
    }

    Ok(result)
}

fn classify_nodata(
    reply: &Message,
    state: &ResolutionState<'_>,
    server: SocketAddr,
    target: AliasTarget,
    result: &mut Classification,
) -> Result<(), ()> {
    // RFC 2308 §2.2 permits CNAME and signature metadata in a
    // NODATA answer, but not contradictory ordinary data.
    if result.restart.is_none()
        && !has_only_negative_answer_metadata(&reply.answers)
        && !has_dname_negative_answer_metadata(&reply.answers, &state.active_question)
    {
        debug!(%server, "discarding DNS response with contradictory CNAME/NODATA data");
        return Err(());
    }
    // An SOA for a target covered by the current authority is
    // authoritative negative proof. A proof beyond a zone
    // boundary or child cut is not.
    if has_soa_for_question(reply, &target.question) {
        if !reply.headers.aa {
            debug!(%server, "discarding non-authoritative CNAME/NODATA response");
            return Err(());
        }
        if target.authoritative {
            result.nodata_question = Some(target.question.clone());
        } else {
            debug!(
                %server,
                target = ?target.name,
                "ignoring CNAME/NODATA proof beyond an authority boundary and resolving target independently"
            );
            result.restart = Some((target.records, target.name, target.question));
        }
    } else {
        result.restart = Some((target.records, target.name, target.question));
    }
    Ok(())
}
