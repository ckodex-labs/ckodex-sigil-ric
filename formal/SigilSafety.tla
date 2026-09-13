---- MODULE SigilSafety ----
EXTENDS Naturals, Sequences

CONSTANTS Severities, Verdicts
VARIABLES stage, tainted, scanned, output

Severities == {"None", "Low", "Medium", "High", "Critical"}
Verdicts == {"Allow", "Flag", "Deny"}

StageOrdering == stage \in {"Init","Intake","Taint","Scan","Merge","Emit","Complete"}
TaintMonotonicity == TRUE
VerdictDeterminism == TRUE
ProvenanceCompleteness == TRUE
CriticalEnforcement == TRUE
EvidenceCompleteness == TRUE
ByteRangeTraceability == TRUE

====
