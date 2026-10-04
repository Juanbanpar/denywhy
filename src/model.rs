use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Proven,
    Strong,
    Possible,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CauseKind {
    ReadOnlyMount,
    NoExecMount,
    Dac,
    PosixAcl,
    StickyDirectory,
    Capability,
}
#[derive(Debug, Serialize)]
pub struct Cause {
    pub kind: CauseKind,
    pub confidence: Confidence,
    pub summary: String,
    pub evidence: Value,
}
