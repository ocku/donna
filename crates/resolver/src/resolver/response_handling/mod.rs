#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

use std::sync::Arc;

mod alias_restart;
mod boundaries;
mod classification;
mod deadlines;
mod dname_chain;
mod preparation;
mod referral;
mod terminal;
mod types;

pub(super) use deadlines::ProofDeadlines;
pub(super) use types::{ResponseAction, ResponseContext, has_minimum_response_structure};

use dns::{Message, QueryType, Question, RCode, RData, RecordType};
use tracing::{debug, warn};
use transport::Transport;

use crate::{
    ResolutionCacheSource, ResolveError,
    protocol::referral,
    response::{
        CnameError, cname_restart, complete_cname_response, delegation_progresses,
        has_dname_negative_answer_metadata, has_only_negative_answer_metadata,
        has_requested_answer, has_soa_for_question, is_terminal_response,
        normalize_response_rrsets,
    },
};

use super::{
    Resolver,
    cache::dname::traversal::{CachedDnameContext, CachedDnameProgress},
    cache::{CachedResolution, CnameCompletedCacheContext},
    state_machine::ResolutionState,
};

impl<T: Transport> Resolver<T> {
    pub(super) async fn process_response<'resolver>(
        &'resolver self,
        context: ResponseContext<'_>,
        reply: Message,
        state: &mut ResolutionState<'resolver>,
    ) -> Result<ResponseAction, ResolveError> {
        let received_at = std::time::Instant::now();
        let preparation::PreparedResponse { reply, cname } =
            match self.prepare_response(&context, reply, state, received_at) {
                Ok(prepared) => prepared,
                Err(action) => return Ok(action),
            };
        let classification = match classification::classify(&reply, state, cname, context.server) {
            Ok(classification) => classification,
            Err(()) => return Ok(ResponseAction::ContinueRound),
        };
        if let Some(chain) = classification.restart {
            return self
                .restart_response_alias(context, reply, chain, received_at, state)
                .await;
        }

        if classification.complete_answer
            || classification.nodata_question.is_some()
            || is_terminal_response(&reply, &state.active_question)
        {
            return self
                .complete_network_terminal(
                    terminal::TerminalContext {
                        original_question: context.original_question,
                        server: context.server,
                        id: context.id,
                        received_at,
                        cname: classification.cname,
                        cname_nodata_question: classification.nodata_question,
                    },
                    reply,
                    state,
                )
                .await;
        }

        self.process_referral(context, reply, state, received_at)
            .await
    }
}
use boundaries::{applicable_child_delegation, delegation_covers_name, trusted_cname_prefix};
