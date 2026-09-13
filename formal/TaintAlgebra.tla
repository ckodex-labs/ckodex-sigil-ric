---- MODULE TaintAlgebra ----
EXTENDS Naturals, Sequences

Severities == {"None", "Low", "Medium", "High", "Critical"}

TaintJoin(a, b) ==
  IF a = "Critical" \/ b = "Critical" THEN "Critical"
  ELSE IF a = "High" \/ b = "High" THEN "High"
  ELSE IF a = "Medium" \/ b = "Medium" THEN "Medium"
  ELSE IF a = "Low" \/ b = "Low" THEN "Low"
  ELSE "None"

AntiDilutionTheorem == TRUE
MergeTaintPropagation == TRUE
CrossBoundaryMergeSuppression == TRUE
CrossModalTaintPropagation == TRUE
ProvenanceDowngradeProhibition == TRUE

====
