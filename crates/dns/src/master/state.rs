use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{ClassType, DomainName, ResourceRecord};

use super::MasterError;
use super::lexer::{Entry, entries};
use super::presentation::{bytes_to_path, decode_character_string, name_from_presentation};
use super::rdata::parse_number;
use super::record::parse_record;

const MAX_INCLUDE_DEPTH: usize = 64;

#[derive(Clone)]
pub(super) struct State {
    pub(super) origin: Option<DomainName>,
    pub(super) owner: Option<DomainName>,
    pub(super) class: Option<ClassType>,
    pub(super) default_ttl: Option<u32>,
    pub(super) last_explicit_ttl: Option<u32>,
    pub(super) base: Option<PathBuf>,
    pub(super) include_stack: Vec<PathBuf>,
}

pub(super) fn parse_entries(
    input: &str,
    state: &mut State,
    records: &mut Vec<ResourceRecord>,
) -> Result<(), MasterError> {
    for entry in entries(input)? {
        parse_entry(entry, state, records)?;
    }
    Ok(())
}

fn parse_entry(
    entry: Entry<'_>,
    state: &mut State,
    records: &mut Vec<ResourceRecord>,
) -> Result<(), MasterError> {
    let fields = &entry.fields;
    if !entry.inherited && entry.first_group.is_none_or(|index| index > 1) && fields.len() > 1 {
        match fields[0].to_ascii_uppercase().as_str() {
            "$ORIGIN" => {
                if fields.len() != 2 || entry.first_group.is_some() {
                    return Err(MasterError::new("$ORIGIN requires one ungrouped name"));
                }
                return parse_origin(fields[1], state);
            }
            "$TTL" if fields[1].bytes().all(|b| b.is_ascii_digit()) => {
                if fields.len() != 2 || entry.first_group.is_some() {
                    return Err(MasterError::new("$TTL requires one ungrouped value"));
                }
                return parse_ttl_directive(fields[1], state);
            }
            "$INCLUDE" => {
                if !(2..=3).contains(&fields.len()) || entry.first_group.is_some() {
                    return Err(MasterError::new(
                        "$INCLUDE requires a filename and optional origin",
                    ));
                }
                return parse_include(&fields[1..], state, records);
            }
            _ => {}
        }
    }
    records.push(parse_record(entry, state)?);
    Ok(())
}

fn parse_origin(value: &str, state: &mut State) -> Result<(), MasterError> {
    state.origin = Some(name_from_presentation(value, state.origin.as_ref())?);
    Ok(())
}

fn parse_ttl_directive(value: &str, state: &mut State) -> Result<(), MasterError> {
    state.default_ttl = Some(parse_number(value, "$TTL")?);
    Ok(())
}

fn parse_include(
    fields: &[&str],
    state: &mut State,
    records: &mut Vec<ResourceRecord>,
) -> Result<(), MasterError> {
    super::lexer::character_string(fields[0])?;
    let filename = decode_character_string(fields[0])?;
    let origin = fields
        .get(1)
        .map(|field| name_from_presentation(field, state.origin.as_ref()))
        .transpose()?;
    let path = include_path(state, &filename)?;
    let path = fs::canonicalize(&path).map_err(|error| {
        MasterError::new(format!(
            "cannot resolve included file {}: {error}",
            path.display()
        ))
    })?;
    if state.include_stack.contains(&path) {
        return Err(MasterError::new(format!(
            "cyclic $INCLUDE detected for {}",
            path.display()
        )));
    }
    if state.include_stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(MasterError::new(format!(
            "$INCLUDE nesting exceeds the maximum depth of {MAX_INCLUDE_DEPTH}"
        )));
    }
    let input = fs::read_to_string(&path).map_err(|error| {
        MasterError::new(format!(
            "cannot read included file {}: {error}",
            path.display()
        ))
    })?;

    parse_included_entries(&input, &path, origin, state, records)
}

fn include_path(state: &State, filename: &[u8]) -> Result<PathBuf, MasterError> {
    let base = state
        .base
        .as_deref()
        .ok_or_else(|| MasterError::new("$INCLUDE requires loading the master file from a path"))?;
    Ok(base.join(bytes_to_path(filename)?))
}

fn parse_included_entries(
    input: &str,
    path: &Path,
    origin: Option<DomainName>,
    state: &mut State,
    records: &mut Vec<ResourceRecord>,
) -> Result<(), MasterError> {
    // RFC 1035 §5.1 restores the parent origin after an insertion. Parser path
    // context is also restored. The insertion remains the source of owner,
    // class, explicit-TTL, and $TTL directive state because RFC 1035 singles out
    // only the included origin for restoration.
    let parent_origin = state.origin.clone();
    let parent_base = state.base.clone();
    if let Some(origin) = origin {
        state.origin = Some(origin);
    }
    state.base = path.parent().map(Path::to_path_buf);
    state.include_stack.push(path.to_path_buf());

    let result = parse_entries(input, state, records);
    state.include_stack.pop();
    state.origin = parent_origin;
    state.base = parent_base;
    result
}
