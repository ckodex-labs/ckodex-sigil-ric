---- MODULE SigilPipeline ----
EXTENDS Naturals, Sequences

CONSTANTS Stages

VARIABLES stage

Stages == {"Init", "Intake", "Taint", "Scan", "Merge", "Emit", "Complete"}

TypeInvariant == stage \in Stages

Init == stage = "Init"

IntakeStep == /\ stage = "Init" /\ stage' = "Intake"
TaintStep == /\ stage = "Intake" /\ stage' = "Taint"
ScanStep == /\ stage = "Taint" /\ stage' = "Scan"
MergeStep == /\ stage = "Scan" /\ stage' = "Merge"
EmitStep == /\ stage = "Merge" /\ stage' = "Emit"
CompleteStep == /\ stage = "Emit" /\ stage' = "Complete"

Next == IntakeStep \/ TaintStep \/ ScanStep \/ MergeStep \/ EmitStep \/ CompleteStep

Spec == Init /\ [][Next]_stage

====
