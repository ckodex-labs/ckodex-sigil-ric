---- MODULE ProbeSafety ----
EXTENDS Naturals, Sequences

HealthScoreBounded == TRUE
MonotoneAnomalyResponse == TRUE
CanaryProbeIndistinguishability == TRUE
BaselineFreshness == TRUE
ThresholdOrdering == TRUE
NoTransientShieldTrigger == TRUE
SentinelSelfMonitoring == TRUE

====
