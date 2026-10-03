# M12 EU AI Act Article 12 field coverage mapping

**Result: 5 of 6 proxy requirements satisfied,the sixth is not met in two
respects.**

## Framing

Article 12 of Regulation (EU) 2024/1689 has three paragraphs. Article 12(1)
requires that high-risk AI systems "technically allow for the automatic
recording of events (logs) over the lifetime of the system". Article 12(2)
requires logging capabilities to enable the recording of events relevant for
identifying risk situations under Articles 79(1), 72 and 26(5).

Article 12(3) specificies a list of required logging fields, but applies 
strictly to remote biometric identification systems (Annex III, point 1(a)). 
Because the AI Act provides no explicit field list for other high risk categories, 
we use the Article 12(3) criteria alongwith general principles in 12(1) and 12(2). 
This serves as a practical proxy benchmark for schema completeness, as opposed to
a claim of direct statutory compliance.

## Mapping

| Article 12 statutory provision | Adapted proxy requirement | Schema field(s) | Status | Notes |
|---|---|---|---|---|
| Art. 12(3)(a): "recording of the period of each use of the system (start date and time and end date and time of each use)" | Period of operation | `timestamp`, `session_id` | Covered (derivable) | Reconstructed as the temporal span from the first to the last entry sharing a `session_id`; not stored as an explicit start/end pair. |
| Art. 12(3)(b): "the reference database against which input data has been checked by the system" | Reference specification in effect | `manifest_hash` | Covered | Uniquely identifies the exact policy manifest version governing the enforcement decision. |
| Art. 12(3)(c): "the input data for which the search has led to a match" | Input data processed | `raw_input` | Covered | Captures tool parameters as submitted, after whitespace and quote normalisation. |
| Art. 12(1): "the automatic recording of events (logs) over the lifetime of the system" | Decision / outcome of processing | `outcome`, `rule_matched`, `reason` | Covered | Each enforcement decision is recorded as a discrete event with the rule triggered and a human readable reason. |
| Art. 12(2): logging that enables "identifying situations that may result in the high risk AI system presenting a risk", "facilitating the post market monitoring" and "monitoring the operation" | Traceability and integrity of the record | `chain_hash`, `prev_hash` | Covered | Modification or deletion of intermediate records is detectable (M9 - M11); removal of trailing records is not, as demonstrated in truncation testing. |
| Art. 12(3)(d): "the identification of the natural persons involved in the verification of the results, as referred to in Article 14(5)" | Identification of responsible party and human verifiers | `owner_id` (manifest level ONLY), no human verification field | Two gaps | See below. |

## Documented gaps

**1. System attribution.** `owner_id` is declared in `manifest.yaml` but is not
propagated into individual audit entries. This was identified during
implementation and deliberately scoped out of the evaluation build. Atribution
is possible via `manifest_hash`. It requires the manifest to persist
and retrievable in parallel with logs, so individual entries are not
self-contained.

*Remediation:* bind `owner_id` into the entry payload before hashing, so the
responsible party is covered by the chain as opposed to referenced externally.

**2. Human verification.** The prototype executes autonomously, human in the loop
confirmation was scoped out of Layer 1. This way no natural person identifiers are
recorded. Art. 12(3)(d) assumes a human verification step, which
this framework does not implement.

*Remediation:* add a confirmation stage for designated high impact tools and
record the confirming identity in the audit entry.

## Scope

This mapping addresses the record-keeping requirements of Article 12 ONLY. It
does not ASSERT compliance with the wider Regulation. Note - Statutory text is quoted
from Regulation (EU) 2024/1689 as published in the Official Journal.