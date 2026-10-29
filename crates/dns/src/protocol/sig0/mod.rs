mod ixfr;
use std::{fmt, sync::Arc};

use ring::signature::{self, KeyPair};

use crate::wire::{
    Decoder, WireError, decode_header, decode_question, decode_record, decode_update_record,
};
use crate::{
    ClassType, DomainName, FromWire, IntoWire, Key, Message, OpCode, QClassType, RData, RecordType,
    ResourceRecord, Sig,
};

/// Ed25519's DNSSEC algorithm number from RFC 8080.
pub const ED25519_DNSSEC_ALGORITHM: u8 = 15;

/// A public KEY and owner name accepted for SIG(0) verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig0VerificationKey {
    name: DomainName,
    key: Key,
}

impl Sig0VerificationKey {
    /// Creates an Ed25519 SIG(0) verification key.
    ///
    /// # Errors
    ///
    /// Returns an error unless the KEY uses protocol 3 or 255, algorithm 15,
    /// and an Ed25519 public key of exactly 32 octets.
    pub fn new(name: DomainName, key: Key) -> Result<Self, Sig0Error> {
        validate_key(&key)?;
        Ok(Self { name, key })
    }

    /// Returns the KEY owner (the SIG signer name).
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// Returns the public KEY RDATA.
    pub const fn key(&self) -> &Key {
        &self.key
    }

    /// Verifies and removes a request SIG(0) from an exact wire image.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid placement, direction, key identity,
    /// validity interval, signature, or DNS wire data.
    pub fn verify_request(&self, wire: &[u8], now: u64) -> Result<VerifiedSig0Message, Sig0Error> {
        let split = split_sig0(wire)?;
        if split.message.headers.qr {
            return Err(Sig0Error::WrongDirection);
        }
        self.verify(split, None, now)
    }

    /// Verifies and removes a response SIG(0), binding it to the full exact
    /// query wire image (including the request SIG(0), if one was present).
    ///
    /// # Errors
    ///
    /// Returns an error for invalid placement, direction, key identity,
    /// validity interval, signature, or DNS wire data.
    pub fn verify_response(
        &self,
        wire: &[u8],
        request_wire: &[u8],
        now: u64,
    ) -> Result<VerifiedSig0Message, Sig0Error> {
        let split = split_sig0(wire)?;
        if !split.message.headers.qr {
            return Err(Sig0Error::WrongDirection);
        }
        self.verify(split, Some(request_wire), now)
    }

    fn verify(
        &self,
        mut split: SplitSig0,
        request_wire: Option<&[u8]>,
        now: u64,
    ) -> Result<VerifiedSig0Message, Sig0Error> {
        let RData::SIG(sig) = &split.record.rdata else {
            unreachable!("split_sig0 requires structured SIG RDATA")
        };
        if !sig.signer_name.eq_dns(&self.name) || sig.key_tag != self.key.key_tag() {
            return Err(Sig0Error::BadKey);
        }
        if sig.algorithm != self.key.algorithm {
            return Err(Sig0Error::BadAlgorithm);
        }
        check_time(sig, now)?;
        let input = signature_input(sig, request_wire, &split.unsigned_wire);
        signature::UnparsedPublicKey::new(&signature::ED25519, &self.key.public_key)
            .verify(&input, &sig.signature)
            .map_err(|_| Sig0Error::BadSignature)?;
        let sig = sig.clone();
        split.message.additionals.pop();
        Ok(VerifiedSig0Message {
            message: split.message,
            sig,
        })
    }
}

/// An Ed25519 private key used to construct RFC 2931 SIG(0) records.
#[derive(Clone)]
pub struct Sig0SigningKey {
    name: DomainName,
    key: Key,
    key_pair: Arc<signature::Ed25519KeyPair>,
}

impl fmt::Debug for Sig0SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Sig0SigningKey")
            .field("name", &self.name)
            .field("key", &self.key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl Sig0SigningKey {
    /// Loads an Ed25519 PKCS#8 private key and derives its public KEY RDATA.
    ///
    /// `protocol` must be 3 (DNSSEC) or 255 (all protocols).
    ///
    /// # Errors
    ///
    /// Returns an error for malformed PKCS#8 data or an invalid KEY protocol.
    pub fn from_ed25519_pkcs8(
        name: DomainName,
        flags: u16,
        protocol: u8,
        pkcs8: &[u8],
    ) -> Result<Self, Sig0Error> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| Sig0Error::InvalidPrivateKey)?;
        let key = Key {
            flags,
            protocol,
            algorithm: ED25519_DNSSEC_ALGORITHM,
            public_key: key_pair.public_key().as_ref().to_vec(),
        };
        validate_key(&key)?;
        Ok(Self {
            name,
            key,
            key_pair: Arc::new(key_pair),
        })
    }

    /// Returns the public verification key corresponding to this signer.
    pub fn verification_key(&self) -> Sig0VerificationKey {
        Sig0VerificationKey {
            name: self.name.clone(),
            key: self.key.clone(),
        }
    }

    /// Signs a request and appends its sole, final SIG(0) additional record.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong direction, an invalid validity interval,
    /// an existing TSIG/SIG(0), or an unencodable message.
    pub fn sign_request(
        &self,
        message: &mut Message,
        inception: u32,
        expiration: u32,
    ) -> Result<Vec<u8>, Sig0Error> {
        if message.headers.qr {
            return Err(Sig0Error::WrongDirection);
        }
        self.sign(message, None, inception, expiration, None)
    }

    /// Signs a response and binds it to the full exact request wire image.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong direction, an invalid validity interval,
    /// an existing TSIG/SIG(0), or an unencodable message.
    pub fn sign_response(
        &self,
        message: &mut Message,
        request_wire: &[u8],
        inception: u32,
        expiration: u32,
    ) -> Result<Vec<u8>, Sig0Error> {
        if !message.headers.qr {
            return Err(Sig0Error::WrongDirection);
        }
        self.sign(message, Some(request_wire), inception, expiration, None)
    }

    fn sign(
        &self,
        message: &mut Message,
        request_wire: Option<&[u8]>,
        inception: u32,
        expiration: u32,
        question: Option<&crate::Question>,
    ) -> Result<Vec<u8>, Sig0Error> {
        ensure_unsigned(message)?;
        if serial_distance(inception, expiration) >= (1_u32 << 31) {
            return Err(Sig0Error::InvalidValidityInterval);
        }
        let unsigned_wire = question
            .map_or_else(|| message.into_wire(), |q| message.into_wire_ixfr(q))
            .map_err(Sig0Error::Wire)?;
        let mut sig = Sig {
            type_covered: 0,
            algorithm: self.key.algorithm,
            labels: 0,
            original_ttl: 0,
            signature_expiration: expiration,
            signature_inception: inception,
            key_tag: self.key.key_tag(),
            signer_name: self.name.clone(),
            signature: Vec::new(),
        };
        let input = signature_input(&sig, request_wire, &unsigned_wire);
        sig.signature = self.key_pair.sign(&input).as_ref().to_vec();
        let signature = sig.signature.clone();
        message.additionals.push(sig0_record(sig));
        Ok(signature)
    }
}

/// A DNS message whose SIG(0) has been authenticated and removed.
#[derive(Debug, Clone)]
pub struct VerifiedSig0Message {
    /// The semantic DNS message without its transaction-only SIG RR.
    pub message: Message,
    /// The authenticated SIG(0) fields.
    pub sig: Sig,
}

/// A SIG(0) construction or authentication failure.
#[derive(Debug)]
pub enum Sig0Error {
    /// The operation was used for the opposite message direction.
    WrongDirection,
    /// No final SIG(0) was present.
    MissingSig0,
    /// SIG(0) was duplicated, misplaced, or had invalid fixed fields.
    InvalidPlacement,
    /// The message already contains SIG(0) or TSIG authentication data.
    AlreadySigned,
    /// The signer name or key tag does not identify this key.
    BadKey,
    /// The DNSSEC algorithm does not match this key.
    BadAlgorithm,
    /// The public-key signature did not verify.
    BadSignature,
    /// The signature is not currently valid.
    BadTime,
    /// The inception/expiration interval is ambiguous under serial arithmetic.
    InvalidValidityInterval,
    /// KEY protocol, algorithm, or public-key data is unsupported or malformed.
    InvalidPublicKey,
    /// PKCS#8 private-key data is malformed.
    InvalidPrivateKey,
    /// DNS wire encoding or decoding failed.
    Wire(WireError),
}

impl fmt::Display for Sig0Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongDirection => formatter.write_str("SIG(0) operation has the wrong direction"),
            Self::MissingSig0 => formatter.write_str("expected a final SIG(0) record"),
            Self::InvalidPlacement => {
                formatter.write_str("SIG(0) is duplicated, misplaced, or malformed")
            }
            Self::AlreadySigned => formatter.write_str("message already contains SIG(0) or TSIG"),
            Self::BadKey => formatter.write_str("SIG(0) key name or tag is not recognized"),
            Self::BadAlgorithm => formatter.write_str("SIG(0) algorithm does not match the key"),
            Self::BadSignature => formatter.write_str("SIG(0) signature verification failed"),
            Self::BadTime => formatter.write_str("SIG(0) is outside its validity interval"),
            Self::InvalidValidityInterval => {
                formatter.write_str("SIG(0) validity interval is ambiguous")
            }
            Self::InvalidPublicKey => {
                formatter.write_str("invalid or unsupported SIG(0) public key")
            }
            Self::InvalidPrivateKey => formatter.write_str("invalid Ed25519 PKCS#8 private key"),
            Self::Wire(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for Sig0Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_key(key: &Key) -> Result<(), Sig0Error> {
    if !matches!(key.protocol, 3 | 255)
        || key.algorithm != ED25519_DNSSEC_ALGORITHM
        || key.public_key.len() != 32
    {
        return Err(Sig0Error::InvalidPublicKey);
    }
    Ok(())
}

fn ensure_unsigned(message: &Message) -> Result<(), Sig0Error> {
    let records = message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals);
    if records.into_iter().any(|record| {
        record.rtype == RecordType::TSIG
            || matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0())
    }) {
        Err(Sig0Error::AlreadySigned)
    } else {
        Ok(())
    }
}

fn sig0_record(sig: Sig) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::SIG,
        class: ClassType::Unknown(255),
        ttl: 0,
        rdata: RData::SIG(sig),
    }
}

fn signature_input(sig: &Sig, request_wire: Option<&[u8]>, unsigned_wire: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&sig.type_covered.to_be_bytes());
    input.push(sig.algorithm);
    input.push(sig.labels);
    input.extend_from_slice(&sig.original_ttl.to_be_bytes());
    input.extend_from_slice(&sig.signature_expiration.to_be_bytes());
    input.extend_from_slice(&sig.signature_inception.to_be_bytes());
    input.extend_from_slice(&sig.key_tag.to_be_bytes());
    append_name(&mut input, &sig.signer_name);
    if let Some(request_wire) = request_wire {
        input.extend_from_slice(request_wire);
    }
    input.extend_from_slice(unsigned_wire);
    input
}

fn append_name(output: &mut Vec<u8>, name: &DomainName) {
    for label in name.as_ref() {
        output.push(label.len() as u8);
        output.extend_from_slice(label);
    }
    output.push(0);
}

fn check_time(sig: &Sig, now: u64) -> Result<(), Sig0Error> {
    let now = now as u32;
    let lifetime = serial_distance(sig.signature_inception, sig.signature_expiration);
    if lifetime >= (1_u32 << 31) || serial_distance(sig.signature_inception, now) > lifetime {
        Err(Sig0Error::BadTime)
    } else {
        Ok(())
    }
}

fn serial_distance(earlier: u32, later: u32) -> u32 {
    later.wrapping_sub(earlier)
}

struct SplitSig0 {
    message: Message,
    record: ResourceRecord,
    unsigned_wire: Vec<u8>,
}

fn split_sig0(wire: &[u8]) -> Result<SplitSig0, Sig0Error> {
    let message = Message::from_wire(wire).map_err(Sig0Error::Wire)?;
    let is_sig0 =
        |record: &ResourceRecord| matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0());
    if message
        .answers
        .iter()
        .chain(&message.authorities)
        .any(is_sig0)
        || message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .any(|record| record.rtype == RecordType::TSIG)
    {
        return Err(Sig0Error::InvalidPlacement);
    }
    let indexes = message
        .additionals
        .iter()
        .enumerate()
        .filter_map(|(index, record)| is_sig0(record).then_some(index))
        .collect::<Vec<_>>();
    if indexes.is_empty() {
        return Err(Sig0Error::MissingSig0);
    }
    if indexes.len() != 1 || indexes[0] + 1 != message.additionals.len() {
        return Err(Sig0Error::InvalidPlacement);
    }
    let record = message.additionals[indexes[0]].clone();
    let RData::SIG(sig) = &record.rdata else {
        unreachable!("SIG(0) predicate requires SIG RDATA")
    };
    if record.rtype != RecordType::SIG || sig.labels != 0 {
        return Err(Sig0Error::InvalidPlacement);
    }
    let sig0_start = last_additional_start(wire)?;
    let mut unsigned_wire = wire[..sig0_start].to_vec();
    let additional_count = u16::from_be_bytes([unsigned_wire[10], unsigned_wire[11]]);
    let unsigned_count = additional_count
        .checked_sub(1)
        .ok_or(Sig0Error::InvalidPlacement)?;
    unsigned_wire[10..12].copy_from_slice(&unsigned_count.to_be_bytes());
    Ok(SplitSig0 {
        message,
        record,
        unsigned_wire,
    })
}

fn last_additional_start(wire: &[u8]) -> Result<usize, Sig0Error> {
    let mut decoder = Decoder::new(wire);
    let (headers, counts) = decode_header(&mut decoder).map_err(Sig0Error::Wire)?;
    let questions = (0..counts.questions)
        .map(|_| decode_question(&mut decoder))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Sig0Error::Wire)?;
    let zone_class = questions
        .first()
        .and_then(|question| match question.qclass {
            QClassType::Class(class) => Some(class),
            QClassType::ANY | QClassType::Unknown(_) => None,
        });
    for _ in 0..counts.answers {
        if headers.opcode == OpCode::Update {
            decode_update_record(&mut decoder, zone_class, true)
        } else {
            decode_record(&mut decoder)
        }
        .map_err(Sig0Error::Wire)?;
    }
    for _ in 0..counts.authorities {
        if headers.opcode == OpCode::Update {
            decode_update_record(&mut decoder, zone_class, false)
        } else {
            decode_record(&mut decoder)
        }
        .map_err(Sig0Error::Wire)?;
    }
    let mut last = None;
    for _ in 0..counts.additionals {
        last = Some(decoder.position());
        decode_record(&mut decoder).map_err(Sig0Error::Wire)?;
    }
    last.ok_or(Sig0Error::MissingSig0)
}

#[cfg(test)]
mod tests;
