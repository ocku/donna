//! Model, parse, validate, encode, and decode DNS data.
//!
//! Use the crate-root protocol types to build DNS messages. Use [`master`] to
//! load zone files and [`wire`] to exchange complete values in DNS wire format.
#![deny(missing_docs)]

mod constants;
pub mod master;
mod protocol;
mod serial;
pub mod wire;

pub use protocol::{
    AuthenticatedDenial, AuthenticatedDnskeySet, AuthenticatedRrset, Caa, CertificateAssociation,
    CertificateAssociationError, CertificateMaterial, ClassType, Csync, DNS_PUSH_RECONFIRM,
    DNS_PUSH_SUBSCRIBE, DNS_PUSH_UNSUBSCRIBE, DNS_PUSH_UPDATE, DSO_KEEPALIVE, DSO_OPCODE,
    DSO_RETRY_DELAY, DiscoverySecurity, DnsPushSubscriptions, DnsSdError, Dnskey,
    DnssecAlgorithmSignal, DnssecAlgorithmSignalError, DnssecAlgorithmStatus, DnssecDenialKind,
    DnssecSecurityStatus, DnssecValidation, DnssecValidationError, DomainName, DomainNameError, Ds,
    DsDigestError, DsoEndpoint, DsoError, DsoMessage, DsoSession, DsoSessionAction, DsoTlv,
    ED25519_DNSSEC_ALGORITHM, EDNS_EXTENDED_DNS_ERROR_OPTION_CODE, EDNS_PADDING_OPTION_CODE,
    EcdsaP256DnssecSigningKey, Edns, EdnsMessageError, EdnsOption, EdnsRecordError,
    ExtendedDnsError, ExtendedDnsErrorCode, ExtendedDnsErrorError, HeaderFieldValueError, Headers,
    Key, LLQ_OPTION_CODE, LLQ_PORT, LLQ_VERSION, LlqClient, LlqClientStatus, LlqError, LlqEventAck,
    LlqEventChange, LlqEventMessage, LlqOpcode, LlqOption, LlqResponseCode, MDNS_HOP_LIMIT,
    MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT, MdnsCache, MdnsDuplicateQuestionCache, MdnsError,
    MdnsPacket, MdnsQuestion, MdnsRecord, MdnsRegistration, MdnsRegistrationAction,
    MdnsRegistrationState, Message, MessageBuilder, MessageValidationError, Nsec, Nsec3,
    Nsec3Chain, Nsec3ChainError, Nsec3ClosestEncloserError, Nsec3ClosestEncloserProof,
    Nsec3HashError, Nsec3ProofError, Nsec3param, OpCode, PaddingOutcome, PaddingPolicyError,
    ProbeTieBreak, PushChange, QClassParseError, QClassType, QueryType, QueryTypeParseError,
    Question, RCode, RData, RECOMMENDED_QUERY_PADDING_BLOCK_SIZE,
    RECOMMENDED_RESPONSE_PADDING_BLOCK_SIZE, RecordType, RecordValidationError, ResolvedService,
    ResourceRecord, Rrsig, RrsigDataError, RrsigSigningError, RrsigVerificationError,
    RsaDnssecSigningKey, SectionCounts, SectionTooLongError, ServiceInstance, ServiceTransport,
    ServiceType, Sig, Sig0Error, Sig0SigningKey, Sig0VerificationKey, TlsaTransport, Tsig,
    TsigAlgorithm, TsigAuthenticationError, TsigErrorCode, TsigKey, TsigRequestAuthentication,
    TsigStreamSigner, TsigStreamVerifier, TxtProperty, TypeBitmap, TypeBitmapError,
    VerifiedSig0Message, VerifiedTsigBatch, VerifiedTsigMessage, append_unsigned_tsig_error,
    authenticate_dnskey_with_anchor, authenticate_dnskey_with_ds, find_nsec3_closest_encloser,
    is_local_name, known_answer_suppresses, llq_service_name, parse_push_reconfirm,
    parse_push_subscribe, parse_push_unsubscribe, parse_push_update, parse_service_txt,
    probe_tie_break, push_reconfirm_tlv, push_subscribe_tlv, push_unsubscribe_tlv, push_update_tlv,
    resolve_services, rfc6944_algorithm_status, service_enumeration_name, smimea_owner_name,
    supports_dnssec_algorithm, supports_ds_digest, tlsa_owner_name, tsig_time_from_unix_duration,
};
pub use serial::SerialNumber;
pub use wire::{FromWire, IntoWire};
