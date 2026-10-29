use super::*;

/// Authenticates a child apex DNSKEY RRset using an authenticated parent DS
/// RRset.
///
/// An empty DS set, or a set containing no combination of supported digest and
/// signing algorithms, yields [`DnssecValidation::Insecure`] as required by
/// RFC 4035 section 5.2 and RFC 6840 section 5.2. Once a supported path exists,
/// failure to match and validate it is bogus.
pub fn authenticate_dnskey_with_ds(
    zone: &DomainName,
    class: ClassType,
    dnskey_records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    authenticated_ds: &[Ds],
    now: u32,
) -> DnssecValidation<AuthenticatedDnskeySet> {
    let supported_ds = authenticated_ds
        .iter()
        .filter(|ds| supports_ds_digest(ds.digest_type) && supports_dnssec_algorithm(ds.algorithm))
        .collect::<Vec<_>>();
    if supported_ds.is_empty() {
        return DnssecValidation::Insecure;
    }
    if !is_dnskey_rrset(zone, class, dnskey_records) {
        return DnssecValidation::Bogus(DnssecValidationError::InvalidRrset);
    }

    let matching_keys = dnskey_records
        .iter()
        .filter(|record| {
            let RData::DNSKEY(key) = &record.rdata else {
                return false;
            };
            supported_ds
                .iter()
                .any(|ds| ds.matches_dnskey(zone, key).unwrap_or(false))
        })
        .collect::<Vec<_>>();
    if matching_keys.is_empty() {
        return DnssecValidation::Bogus(DnssecValidationError::NoMatchingDs);
    }

    match verify_with_candidate_keys(dnskey_records, signatures, zone, &matching_keys, now) {
        Ok(authenticated) => DnssecValidation::Secure(AuthenticatedDnskeySet {
            zone: zone.clone(),
            class,
            records: dnskey_records.to_vec().into(),
            authenticated_ttl: authenticated.authenticated_ttl,
            signature_expiration: authenticated.signature_expiration,
            soa_signature: Default::default(),
            dname_signature: Default::default(),
            denial_signatures: None,
        }),
        Err(error) => DnssecValidation::Bogus(error),
    }
}

/// Authenticates an apex DNSKEY RRset using a configured DNSKEY trust anchor.
pub fn authenticate_dnskey_with_anchor(
    zone: &DomainName,
    class: ClassType,
    dnskey_records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    trust_anchor: &Dnskey,
    now: u32,
) -> DnssecValidation<AuthenticatedDnskeySet> {
    if !is_dnskey_rrset(zone, class, dnskey_records) {
        return DnssecValidation::Bogus(DnssecValidationError::InvalidRrset);
    }
    let Some(anchor_record) = dnskey_records
        .iter()
        .find(|record| matches!(&record.rdata, RData::DNSKEY(key) if key == trust_anchor))
    else {
        return DnssecValidation::Bogus(DnssecValidationError::MissingTrustAnchor);
    };
    if !supports_dnssec_algorithm(trust_anchor.algorithm) {
        return DnssecValidation::Indeterminate(DnssecValidationError::NoValidSignature);
    }

    match verify_with_candidate_keys(dnskey_records, signatures, zone, &[anchor_record], now) {
        Ok(authenticated) => DnssecValidation::Secure(AuthenticatedDnskeySet {
            zone: zone.clone(),
            class,
            records: dnskey_records.to_vec().into(),
            authenticated_ttl: authenticated.authenticated_ttl,
            signature_expiration: authenticated.signature_expiration,
            soa_signature: Default::default(),
            dname_signature: Default::default(),
            denial_signatures: None,
        }),
        Err(error) => DnssecValidation::Bogus(error),
    }
}

pub(super) fn validate_rrset_with_keys(
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    signer_name: &DomainName,
    keys: &[ResourceRecord],
    now: u32,
    cache: Option<&crate::protocol::SuccessfulSignatureCache>,
) -> DnssecValidation<AuthenticatedRrset> {
    if records.is_empty() || !same_rrset(records) || !records[0].name.is_descendant_of(signer_name)
    {
        return DnssecValidation::Bogus(DnssecValidationError::InvalidRrset);
    }
    let key_refs = keys.iter().collect::<Vec<_>>();
    match verify_with_candidate_keys_cached(records, signatures, signer_name, &key_refs, now, cache)
    {
        Ok(authenticated) => DnssecValidation::Secure(authenticated),
        Err(error) => DnssecValidation::Bogus(error),
    }
}

pub(super) fn verify_with_candidate_keys(
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    signer_name: &DomainName,
    keys: &[&ResourceRecord],
    now: u32,
) -> Result<AuthenticatedRrset, DnssecValidationError> {
    verify_with_candidate_keys_cached(records, signatures, signer_name, keys, now, None)
}

fn verify_with_candidate_keys_cached(
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    signer_name: &DomainName,
    keys: &[&ResourceRecord],
    now: u32,
    cache: Option<&crate::protocol::SuccessfulSignatureCache>,
) -> Result<AuthenticatedRrset, DnssecValidationError> {
    if records.is_empty() || !same_rrset(records) {
        return Err(DnssecValidationError::InvalidRrset);
    }
    let first = &records[0];
    let mut last_error = None;
    for signature_record in signatures {
        let RData::RRSIG(rrsig) = &signature_record.rdata else {
            continue;
        };
        if signature_record.rtype != RecordType::RRSIG
            || !signature_record.name.eq_dns(&first.name)
            || signature_record.class != first.class
            || rrsig.type_covered != u16::from(first.rtype)
            || !rrsig.signer_name.eq_dns(signer_name)
            || !supports_dnssec_algorithm(rrsig.algorithm)
        {
            continue;
        }
        for key_record in keys {
            let RData::DNSKEY(key) = &key_record.rdata else {
                continue;
            };
            if key_record.rtype != RecordType::DNSKEY
                || !key_record.name.eq_dns(signer_name)
                || key_record.class != first.class
                || key.algorithm != rrsig.algorithm
                || key.key_tag() != rrsig.key_tag
            {
                continue;
            }
            match rrsig.verify_with_cache(records, signer_name, key, now, cache) {
                Ok(()) => {
                    let ttl = authenticated_ttl(records, signature_record, rrsig, now);
                    return Ok(AuthenticatedRrset {
                        authenticated_ttl: ttl,
                        signature_expiration: rrsig.signature_expiration,
                        signing_key_tag: key.key_tag(),
                        wildcard_closest_encloser: wildcard_closest_encloser(&first.name, rrsig),
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
    }
    Err(last_error.map_or(
        DnssecValidationError::NoValidSignature,
        DnssecValidationError::Signature,
    ))
}

pub(super) fn same_rrset(records: &[ResourceRecord]) -> bool {
    let Some(first) = records.first() else {
        return false;
    };
    records.iter().all(|record| {
        record.name.eq_dns(&first.name)
            && record.rtype == first.rtype
            && record.class == first.class
            && record.validate().is_ok()
    })
}

pub(super) fn is_dnskey_rrset(
    zone: &DomainName,
    class: ClassType,
    records: &[ResourceRecord],
) -> bool {
    !records.is_empty()
        && records.iter().all(|record| {
            record.name.eq_dns(zone)
                && record.rtype == RecordType::DNSKEY
                && record.class == class
                && matches!(record.rdata, RData::DNSKEY(_))
                && record.validate().is_ok()
        })
}

pub(super) fn authenticated_ttl(
    records: &[ResourceRecord],
    signature_record: &ResourceRecord,
    rrsig: &Rrsig,
    now: u32,
) -> u32 {
    let received_ttl = records.iter().map(|record| record.ttl).min().unwrap_or(0);
    received_ttl
        .min(signature_record.ttl)
        .min(rrsig.original_ttl)
        .min(rrsig.signature_expiration.wrapping_sub(now))
}

pub(super) fn wildcard_closest_encloser(owner: &DomainName, rrsig: &Rrsig) -> Option<DomainName> {
    let labels = usize::from(rrsig.labels);
    let owner_labels = owner.as_ref();
    if labels >= owner_labels.len() {
        return None;
    }
    Some(
        DomainName::from_labels(owner_labels[owner_labels.len() - labels..].to_vec())
            .expect("a suffix of a valid domain name is valid"),
    )
}

pub(super) fn wildcard_name(closest_encloser: &DomainName) -> Result<DomainName, ()> {
    let mut labels = Vec::with_capacity(closest_encloser.as_ref().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend_from_slice(closest_encloser.as_ref());
    DomainName::from_labels(labels).map_err(|_| ())
}

pub(super) fn next_closer_name(
    qname: &DomainName,
    closest_encloser: &DomainName,
) -> Option<DomainName> {
    if !qname.is_descendant_of(closest_encloser)
        || qname.as_ref().len() <= closest_encloser.as_ref().len()
    {
        return None;
    }
    let first_label = qname.as_ref().len() - closest_encloser.as_ref().len() - 1;
    DomainName::from_labels(qname.as_ref()[first_label..].to_vec()).ok()
}

pub(super) fn unsafe_closest_encloser_bitmap(codes: &[u16]) -> bool {
    codes.contains(&39)
        || (codes.contains(&u16::from(RecordType::NS))
            && !codes.contains(&u16::from(RecordType::SOA)))
}

pub(super) fn unsafe_denial_bitmap(codes: &[u16], qtype: u16) -> bool {
    codes.contains(&39)
        || (qtype != u16::from(RecordType::DS)
            && codes.contains(&u16::from(RecordType::NS))
            && !codes.contains(&u16::from(RecordType::SOA)))
}

pub(super) fn denial_kind(qtype: u16, codes: &[u16]) -> DnssecDenialKind {
    if qtype == u16::from(RecordType::DS)
        && codes.contains(&u16::from(RecordType::NS))
        && !codes.contains(&u16::from(RecordType::SOA))
    {
        DnssecDenialKind::UnsignedDelegation
    } else {
        DnssecDenialKind::NoData
    }
}
