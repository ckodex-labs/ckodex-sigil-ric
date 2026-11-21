//! Identity of the interpreter that produced a perception channel (RIC-R-4).
//!
//! An extractor's output is decided by more than its binary: the argument
//! vector selects the resampler or page segmentation mode, and the model
//! weights decide what is heard or read. Identity v2 binds all three:
//!
//! ```text
//! identity_digest = SHA-384(
//!     lp("sigil-extractor-identity-v2")
//!   ‖ lp(config_digest)
//!   ‖ u64be(len(args))   ‖ lp(arg)…
//!   ‖ u64be(len(models)) ‖ lp(model_digest)…   // sorted ascending
//! )
//! lp(x) = u64be(len(x)) ‖ x
//! ```
//!
//! Every field is length-prefixed and every list carries its count, so no two
//! distinct (digest, args, models) triples share an encoding: moving a byte
//! between two arguments, or from an argument to a model digest, changes the
//! input to SHA-384.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

/// Identity records written before v2: `config_digest` is the external
/// binary's digest, or for in-process extractors the artifact digest.
pub const EXTRACTOR_IDENTITY_V1: u32 = 1;
/// Binds binary (or implementation) digest, arguments and model digests.
/// `config_digest` never carries the artifact digest.
pub const EXTRACTOR_IDENTITY_V2: u32 = 2;

const IDENTITY_DOMAIN: &[u8] = b"sigil-extractor-identity-v2";
const IN_PROCESS_DOMAIN: &[u8] = b"sigil-in-process-extractor-v1";

/// Identity of the extractor that produced a channel. Recorded so "which OCR,
/// run how, with which weights, produced this text" is answerable from the
/// evidence chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractorIdentity {
    pub name: String,
    pub version: String,
    /// SHA-384 (hex) of the external binary, or of an in-process extractor's
    /// implementation descriptor (see [`ExtractorIdentity::in_process`]).
    /// In v1 records an in-process extractor stored the artifact digest here.
    pub config_digest: String,
    /// Evidence format; records without the field are v1.
    #[serde(default = "identity_v1")]
    pub identity_version: u32,
    /// Argument vector, or `key=value` configuration for in-process extractors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// SHA-384 (hex) of each declared model artifact, sorted ascending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_digests: Vec<String>,
    /// v2 identity over (config_digest, args, model_digests). Empty in v1.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity_digest: String,
}

fn identity_v1() -> u32 {
    EXTRACTOR_IDENTITY_V1
}

impl ExtractorIdentity {
    /// A v2 identity binding `config_digest`, `args` and the model digests
    /// (sorted here, so declaration order does not change the identity).
    #[must_use]
    pub fn bound(
        name: String,
        version: String,
        config_digest: String,
        args: Vec<String>,
        mut model_digests: Vec<String>,
    ) -> Self {
        model_digests.sort();
        let identity_digest = identity_digest(&config_digest, &args, &model_digests);
        Self {
            name,
            version,
            config_digest,
            identity_version: EXTRACTOR_IDENTITY_V2,
            args,
            model_digests,
            identity_digest,
        }
    }

    /// A v2 identity for an extractor that runs inside SIGIL. Its
    /// `config_digest` is SHA-384 over the name, version and the ordered
    /// `key=value` descriptor of everything that decides its output.
    #[must_use]
    pub fn in_process(name: String, version: String, descriptor: &[(&str, String)]) -> Self {
        let args: Vec<String> = descriptor.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut hasher = Sha384::new();
        put(&mut hasher, IN_PROCESS_DOMAIN);
        put(&mut hasher, name.as_bytes());
        put(&mut hasher, version.as_bytes());
        put_list(&mut hasher, &args);
        let config_digest = hex(&hasher.finalize());
        Self::bound(name, version, config_digest, args, Vec::new())
    }

    /// True when a v2 record's `identity_digest` matches its own fields and
    /// its model list is sorted. v1 records carry no identity digest and are
    /// never self-consistent in this sense.
    #[must_use]
    pub fn is_self_consistent(&self) -> bool {
        self.identity_version == EXTRACTOR_IDENTITY_V2
            && self.model_digests.is_sorted()
            && self.identity_digest
                == identity_digest(&self.config_digest, &self.args, &self.model_digests)
    }
}

fn identity_digest(config_digest: &str, args: &[String], model_digests: &[String]) -> String {
    let mut hasher = Sha384::new();
    put(&mut hasher, IDENTITY_DOMAIN);
    put(&mut hasher, config_digest.as_bytes());
    put_list(&mut hasher, args);
    put_list(&mut hasher, model_digests);
    hex(&hasher.finalize())
}

fn put(hasher: &mut Sha384, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn put_list(hasher: &mut Sha384, items: &[String]) {
    hasher.update((items.len() as u64).to_be_bytes());
    for item in items {
        put(hasher, item.as_bytes());
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
