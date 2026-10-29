use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
    fmt,
};

use rsa::{
    pkcs8::DecodePrivateKey,
    signature::{SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
};

use crate::{
    ClassType, DomainName, DomainNameError, RData, RecordType, RecordValidationError,
    ResourceRecord, TypeBitmap, TypeBitmapError,
};

/// DS RDATA identifying a child-zone DNSKEY.
mod canonical;
mod dnskey;
mod nsec;
mod nsec3_chain;
mod nsec3_proof;
mod rrsig;
mod verification;

pub use canonical::RrsigDataError;
pub(crate) use canonical::canonical_name_cmp;
pub use dnskey::{Dnskey, Ds, DsDigestError};
pub use nsec::{Nsec, Nsec3, Nsec3param};
pub use nsec3_chain::{Nsec3Chain, Nsec3ChainError, Nsec3HashError};
pub use nsec3_proof::{
    Nsec3ClosestEncloserError, Nsec3ClosestEncloserProof, Nsec3ProofError,
    find_nsec3_closest_encloser,
};
pub use rrsig::{EcdsaP256DnssecSigningKey, Rrsig, RsaDnssecSigningKey};
pub use verification::{RrsigSigningError, RrsigVerificationError};

use canonical::{canonical_rdata, signed_owner, write_canonical_name};
#[cfg(test)]
use nsec3_proof::decode_base32hex_label;
use nsec3_proof::{
    base32hex, nsec3_hash, nsec3_hash_fixed, nsec3_hash_labels_fixed, nsec3_owner_hash,
};
use verification::{verify_ecdsa_p256, verify_rsa};

#[cfg(test)]
mod tests;
