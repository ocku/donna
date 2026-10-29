use std::net::IpAddr;

use dns::{IntoWire, Message, ResourceRecord, TsigStreamSigner};
use tokio::sync::mpsc;

use crate::response::base_response;

pub(super) fn address_matches(network: IpAddr, netmask: IpAddr, address: IpAddr) -> bool {
    match (network, netmask, address) {
        (IpAddr::V4(network), IpAddr::V4(netmask), IpAddr::V4(address)) => network
            .octets()
            .iter()
            .zip(netmask.octets())
            .zip(address.octets())
            .all(|((&network, netmask), address)| network & netmask == address & netmask),
        (IpAddr::V6(network), IpAddr::V6(netmask), IpAddr::V6(address)) => network
            .octets()
            .iter()
            .zip(netmask.octets())
            .zip(address.octets())
            .all(|((&network, netmask), address)| network & netmask == address & netmask),
        _ => false,
    }
}

pub(super) fn pack_axfr_responses(
    query: &Message,
    records: impl Iterator<Item = ResourceRecord>,
) -> Option<Vec<Message>> {
    let mut packer = AxfrResponsePacker::new(query, records, 0);
    let mut responses = Vec::new();
    while let Some(response) = packer.next_response().ok()? {
        responses.push(response);
    }
    (!responses.is_empty()).then_some(responses)
}

pub(super) async fn stream_axfr_responses(
    query: &Message,
    records: impl Iterator<Item = ResourceRecord>,
    responses: mpsc::Sender<Message>,
    mut signing: Option<TsigStreamSigning>,
) -> bool {
    // Leave ample room for the final TSIG RR when stream authentication is
    // enabled; otherwise a maximally packed unsigned frame could become
    // unencodable after signing.
    let reserved_octets = if signing.is_some() { 512 } else { 0 };
    let mut packer = AxfrResponsePacker::new(query, records, reserved_octets);
    let mut produced = false;
    loop {
        // Reserve before advancing the packer so a full bounded channel stops
        // record cloning and frame construction, not merely the final send.
        let Ok(permit) = responses.reserve().await else {
            return false;
        };
        match packer.next_response() {
            Ok(Some(mut response)) => {
                if let Some(signing) = &mut signing
                    && signing
                        .signer
                        .sign_next(
                            &mut response,
                            signing.original_id,
                            super::tsig::unix_time_now(),
                            signing.fudge,
                            None,
                        )
                        .is_err()
                {
                    return false;
                }
                permit.send(response);
                produced = true;
            }
            Ok(None) => return produced,
            Err(()) => return false,
        }
    }
}

pub(super) struct TsigStreamSigning {
    pub(super) signer: TsigStreamSigner,
    pub(super) original_id: u16,
    pub(super) fudge: u16,
}

struct AxfrResponsePacker<'a, I> {
    query: &'a Message,
    records: I,
    pending: Option<ResourceRecord>,
    first_message: bool,
    finished: bool,
    reserved_octets: usize,
}

impl<'a, I> AxfrResponsePacker<'a, I>
where
    I: Iterator<Item = ResourceRecord>,
{
    fn new(query: &'a Message, records: I, reserved_octets: usize) -> Self {
        Self {
            query,
            records,
            pending: None,
            first_message: true,
            finished: false,
            reserved_octets,
        }
    }

    fn next_response(&mut self) -> Result<Option<Message>, ()> {
        if self.finished {
            return Ok(None);
        }

        let mut response = axfr_response(self.query, self.first_message);
        loop {
            let record = self.pending.take().or_else(|| self.records.next());
            let Some(record) = record else {
                self.finished = true;
                if response.answers.is_empty() {
                    return Ok(None);
                }
                self.first_message = false;
                return Ok(Some(response));
            };

            response.answers.push(record);
            if response
                .into_wire()
                .is_ok_and(|wire| wire.len() + self.reserved_octets <= usize::from(u16::MAX))
            {
                continue;
            }

            let record = response
                .answers
                .pop()
                .expect("the candidate record was pushed");
            if response.answers.is_empty() {
                return Err(());
            }
            self.pending = Some(record);
            self.first_message = false;
            return Ok(Some(response));
        }
    }
}

fn axfr_response(query: &Message, include_question: bool) -> Message {
    let mut response = base_response(query);
    response.headers.aa = true;
    if !include_question {
        response.questions.clear();
    }
    response
}
