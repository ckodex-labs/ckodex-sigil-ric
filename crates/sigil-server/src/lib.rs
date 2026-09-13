//! SIGIL server façade.
//!
//! This crate provides a sidecar-style composition layer across SIGIL-core,
//! SIGIL-MCP, SIGIL-PROBE, SIGIL-M, and SIGIL-S.

use sigil_core::{
    engine::Sigil,
    policy::Policy,
    types::{InputAssessment, Provenance, SigilOutput, TextSegment},
    Vocab,
};
use sigil_mcp::{McpGate, McpInspection, McpScanConfig, McpSession, ResponseSchema};
use sigil_multimodal::{ModalInput, MultimodalAssessment, MultimodalEngine};
use sigil_probe::{BaselineProfile, HealthReport, ProbeConfig, ProbeEngine, ProbeSample};
use sigil_s::{compose_with_sigil, CompositeVerdict, SentinelModel, SentinelVerdict};

#[derive(Clone, Debug)]
pub struct SidecarConfig {
    pub policy: Policy,
    pub vocab: Vocab,
    pub mcp: McpScanConfig,
    pub probe: ProbeConfig,
    pub baseline_samples: Vec<ProbeSample>,
    pub sentinel: SentinelModel,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            vocab: Vocab::tiktoken("cl100k_base"),
            mcp: McpScanConfig::default(),
            probe: ProbeConfig::default(),
            baseline_samples: Vec::new(),
            sentinel: SentinelModel::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigilSidecar {
    core: Sigil,
    mcp_session: McpSession,
    probe: ProbeEngine,
    multimodal: MultimodalEngine,
    sentinel: SentinelModel,
}

impl SigilSidecar {
    pub fn new(config: SidecarConfig) -> sigil_core::Result<Self> {
        let policy = config.policy.clone();
        let vocab = config.vocab.clone();
        let core = Sigil::new(vocab.clone(), policy.clone())?;
        let mcp_session = McpSession::new(McpGate::new(policy.clone(), config.mcp, vocab.clone())?);
        let probe = ProbeEngine::new(
            BaselineProfile::from_samples(&config.baseline_samples),
            config.probe,
        );
        let multimodal = MultimodalEngine::new(policy, vocab)?;

        Ok(Self {
            core,
            mcp_session,
            probe,
            multimodal,
            sentinel: config.sentinel,
        })
    }

    pub fn inspect_text(&self, text: &str) -> sigil_core::Result<SigilOutput> {
        self.core.process_text_segments(&[TextSegment {
            text,
            provenance: Provenance::User,
        }])
    }

    pub fn inspect_mcp_response(
        &mut self,
        server_id: &str,
        request_hash: &str,
        response: &str,
        schema: Option<&ResponseSchema>,
    ) -> sigil_core::Result<McpInspection> {
        self.mcp_session
            .inspect_response(server_id, request_hash, response, schema)
    }

    pub fn inspect_multimodal(
        &self,
        inputs: &[ModalInput],
    ) -> sigil_core::Result<MultimodalAssessment> {
        self.multimodal.analyze(inputs)
    }

    pub fn inspect_sentinel(
        &self,
        text: &str,
        assessment: Option<&InputAssessment>,
    ) -> SentinelVerdict {
        self.sentinel.classify(text, assessment)
    }

    pub fn compose_sentinel(
        &self,
        assessment: &InputAssessment,
        sentinel: &SentinelVerdict,
    ) -> CompositeVerdict {
        compose_with_sigil(assessment, sentinel)
    }

    pub fn probe_health(
        &self,
        samples: &[ProbeSample],
        canaries: &[sigil_probe::CanaryCase],
        fingerprints: &[sigil_probe::FingerprintProbe],
        boundaries: &[sigil_probe::BoundaryProbe],
    ) -> HealthReport {
        self.probe
            .analyze(samples, canaries, fingerprints, boundaries)
    }

    pub fn mcp_session_mut(&mut self) -> &mut McpSession {
        &mut self.mcp_session
    }
}
