use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;

fn origin() -> DomainName {
    DomainName::from_labels(vec![b"example".to_vec(), b"test".to_vec()]).unwrap()
}

mod basic_records;
mod directives_and_includes;
mod dnssec;
mod names_and_zone_validation;

mod generic;

mod legacy_security;
mod lexer_differential;
