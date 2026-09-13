---- MODULE SigilMcpSafety ----
EXTENDS Naturals, Sequences

CONSTANTS McpServers
VARIABLES server_trust, accumulated_taint, mcp_evidence

NoUnscannedMcpContent == TRUE
McpTrustMonotonicity == TRUE
CrossToolTaintAccumulation == TRUE
McpTokenBudgetEnforcement == TRUE
McpSchemaConformance == TRUE
McpEvidenceCompleteness == TRUE

====
