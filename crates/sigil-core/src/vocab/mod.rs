mod encode;
mod tables;

use crate::types::{ByteRange, Provenance, TrustLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct Vocab {
    pub name: String,
    pub unknown_token_id: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncodedToken {
    pub token_id: u32,
    pub text: String,
    pub byte_range: ByteRange,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
    pub normalized: bool,
    pub boundary: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum SpecialTokenMode {
    #[default]
    Disallow,
    AllowAll,
    AllowOnly(HashSet<String>),
}

#[derive(Clone, Copy)]
pub(crate) struct MaterializationContext<'a> {
    pub(crate) text: &'a str,
    pub(crate) base_offset: usize,
    pub(crate) provenance: Provenance,
    pub(crate) trust_level: TrustLevel,
    pub(crate) normalized: bool,
    pub(crate) boundary: bool,
}
