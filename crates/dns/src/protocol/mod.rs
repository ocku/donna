/// DNS-Based Service Discovery naming, TXT, browse, and resolve behavior.
///
/// RFC 6763: <https://www.rfc-editor.org/rfc/rfc6763>
mod dnssd;
/// DNSSEC chain-of-trust and RRset validation.
///
/// RFC 4033, RFC 4035, and RFC 6840.
mod dnssec;
mod mac;
mod signature_cache;
pub(crate) use signature_cache::SuccessfulSignatureCache;
/// DNS Stateful Operations and DNS Push Notifications.
///
/// RFC 8490 and RFC 8765.
mod dso;
/// EDNS control information and option tuples.
///
/// RFC 6891: <https://www.rfc-editor.org/rfc/rfc6891>
mod edns;
/// Apple's legacy DNS Long-Lived Queries option and client state machine.
///
/// RFC 8764 (Informational).
mod llq;
/// Multicast DNS packet, scope, cache, and suppression semantics.
///
/// RFC 6762: <https://www.rfc-editor.org/rfc/rfc6762>
mod mdns;
/// DNS message structure and name encoding.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-4>
mod message;
/// DNS resource-record types and wire formats.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3>
mod resource_record;
/// Public-key transaction signatures.
///
/// RFC 2931: <https://www.rfc-editor.org/rfc/rfc2931>
mod sig0;
/// Transaction Signature authentication and verification.
///
/// RFC 8945: <https://www.rfc-editor.org/rfc/rfc8945>
mod tsig;

pub use dnssd::{
    DiscoverySecurity, DnsSdError, ResolvedService, ServiceInstance, ServiceTransport, ServiceType,
    TxtProperty, parse_service_txt, resolve_services, service_enumeration_name,
};
pub use dnssec::{
    AuthenticatedDenial, AuthenticatedDnskeySet, AuthenticatedRrset, DnssecAlgorithmStatus,
    DnssecDenialKind, DnssecSecurityStatus, DnssecValidation, DnssecValidationError,
    authenticate_dnskey_with_anchor, authenticate_dnskey_with_ds, rfc6944_algorithm_status,
    supports_dnssec_algorithm, supports_ds_digest,
};
pub use dso::{
    DNS_PUSH_RECONFIRM, DNS_PUSH_SUBSCRIBE, DNS_PUSH_UNSUBSCRIBE, DNS_PUSH_UPDATE, DSO_KEEPALIVE,
    DSO_OPCODE, DSO_RETRY_DELAY, DnsPushSubscriptions, DsoEndpoint, DsoError, DsoMessage,
    DsoSession, DsoSessionAction, DsoTlv, PushChange, parse_push_reconfirm, parse_push_subscribe,
    parse_push_unsubscribe, parse_push_update, push_reconfirm_tlv, push_subscribe_tlv,
    push_unsubscribe_tlv, push_update_tlv,
};
pub use edns::{
    DnssecAlgorithmSignal, DnssecAlgorithmSignalError, EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
    EDNS_PADDING_OPTION_CODE, Edns, EdnsMessageError, EdnsOption, EdnsRecordError,
    ExtendedDnsError, ExtendedDnsErrorCode, ExtendedDnsErrorError, PaddingOutcome,
    PaddingPolicyError, RECOMMENDED_QUERY_PADDING_BLOCK_SIZE,
    RECOMMENDED_RESPONSE_PADDING_BLOCK_SIZE,
};
pub use llq::{
    LLQ_OPTION_CODE, LLQ_PORT, LLQ_VERSION, LlqClient, LlqClientStatus, LlqError, LlqEventAck,
    LlqEventChange, LlqEventMessage, LlqOpcode, LlqOption, LlqResponseCode, llq_service_name,
};
pub use mdns::{
    MDNS_HOP_LIMIT, MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT, MdnsCache,
    MdnsDuplicateQuestionCache, MdnsError, MdnsPacket, MdnsQuestion, MdnsRecord, MdnsRegistration,
    MdnsRegistrationAction, MdnsRegistrationState, ProbeTieBreak, is_local_name,
    known_answer_suppresses, probe_tie_break,
};
pub(crate) use message::QuestionValidationError;
pub use message::{
    DomainName, DomainNameError, HeaderFieldValueError, Headers, Message, MessageBuilder,
    MessageValidationError, OpCode, QueryType, QueryTypeParseError, Question, RCode, SectionCounts,
    SectionTooLongError,
};
pub(crate) use resource_record::validate_zone_records;
pub use resource_record::{
    Caa, CertificateAssociation, CertificateAssociationError, CertificateMaterial, ClassType,
    Csync, Dnskey, Ds, DsDigestError, EcdsaP256DnssecSigningKey, Key, Nsec, Nsec3, Nsec3Chain,
    Nsec3ChainError, Nsec3ClosestEncloserError, Nsec3ClosestEncloserProof, Nsec3HashError,
    Nsec3ProofError, Nsec3param, QClassParseError, QClassType, RData, RecordType,
    RecordValidationError, ResourceRecord, Rrsig, RrsigDataError, RrsigSigningError,
    RrsigVerificationError, RsaDnssecSigningKey, Sig, TlsaTransport, Tsig, TsigAlgorithm,
    TsigErrorCode, TypeBitmap, TypeBitmapError, find_nsec3_closest_encloser, smimea_owner_name,
    tlsa_owner_name,
};
pub(crate) use resource_record::{is_valid_caa_property_tag, validate_rdata_forwarded};
pub use sig0::{
    ED25519_DNSSEC_ALGORITHM, Sig0Error, Sig0SigningKey, Sig0VerificationKey, VerifiedSig0Message,
};
pub use tsig::{
    TsigAuthenticationError, TsigKey, TsigRequestAuthentication, TsigStreamSigner,
    TsigStreamVerifier, VerifiedTsigBatch, VerifiedTsigMessage, append_unsigned_tsig_error,
    tsig_time_from_unix_duration,
};
