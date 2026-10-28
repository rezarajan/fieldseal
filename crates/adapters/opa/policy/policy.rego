# Fieldseal decision points as Rego (docs/reference/spec/policy.md section 6.2).
#
# This file mirrors the reference engine (BuiltInPolicyEngine in fieldseal-adapters-memory)
# rule for rule: the same reason codes, the same verdict precedence (deny, then hold, then
# flag, then allow) and the same obligations. `fieldseal_policy::contract::engine_cases()` is
# the table both must match.
#
# Input (built and type-checked by the adapter before OPA sees it, so a missing or mistyped
# fact never reaches a rule):
#   input.point    the decision point name
#   input.facts    the facts the point reads (durations in seconds, sizes in bytes;
#                  `sampleDraw` as a decimal string)
#   input.policy   the effective policy's controls this engine reads: durations in seconds,
#                  sizes in bytes, `sampleRate` as a decimal string, dates as YYYY-MM-DD
#
# Output: data.fieldseal.policy.decision, {verdict, reasons, obligations}. Reasons and
# obligations are sorted so the output is deterministic (POL-032).
package fieldseal.policy

rank := {"allow": 0, "flag": 1, "hold": 2, "deny": 3}

levels := {"tee": 0, "strongbox": 1, "secure-element": 2, "tpm": 3}

facts := input.facts

# ---- registration.token.issue ----------------------------------------------------------

token := input.policy.factory.registration

findings contains {"verdict": "deny", "reason": "phishing-resistant-auth-required"} if {
	input.point == "registration.token.issue"
	token.requirePhishingResistantAuth
	facts.phishingResistantAuth == false
}

findings contains {"verdict": "deny", "reason": "batch-tokens-not-allowed"} if {
	input.point == "registration.token.issue"
	facts.batch
	token.batchTokens.allowed == false
}

findings contains {"verdict": "deny", "reason": "batch-role-not-allowed"} if {
	input.point == "registration.token.issue"
	facts.batch
	token.batchTokens.allowed
	not facts.role in token.batchTokens.roles
}

token_limit := token.batchTokens.ttl if facts.batch

token_limit := token.airGappedTokenTtl if {
	not facts.batch
	facts.airGapped
}

token_limit := token.tokenTtl if {
	not facts.batch
	not facts.airGapped
}

findings contains {"verdict": "deny", "reason": "ttl-exceeds-policy"} if {
	input.point == "registration.token.issue"
	facts.requestedTtlSeconds > token_limit
}

# ---- registration.approve --------------------------------------------------------------

findings contains {"verdict": "hold", "reason": "fingerprint-unconfirmed"} if {
	input.point == "registration.approve"
	token.requireFingerprintConfirmation
	facts.fingerprintConfirmed == false
}

findings contains {"verdict": "deny", "reason": "serial-mismatch"} if {
	input.point == "registration.approve"
	token.serialCheck == "required"
	facts.serialStatus == "unmatched"
}

findings contains {"verdict": "hold", "reason": "serial-missing"} if {
	input.point == "registration.approve"
	token.serialCheck == "required"
	facts.serialStatus == "absent"
}

findings contains {"verdict": "hold", "reason": "serial-mismatch-review"} if {
	input.point == "registration.approve"
	token.serialCheck == "optional"
	facts.serialStatus == "unmatched"
}

findings contains {"verdict": "flag", "reason": "device-nonce-registration"} if {
	input.point == "registration.approve"
	facts.nonceOnly
	token.deviceNonceRegistrations == "flag"
}

findings contains {"verdict": "deny", "reason": "device-nonce-registration-denied"} if {
	input.point == "registration.approve"
	facts.nonceOnly
	token.deviceNonceRegistrations == "deny"
}

# ---- device.add ------------------------------------------------------------------------

findings contains {"verdict": "deny", "reason": "device-limit-reached"} if {
	input.point == "device.add"
	facts.activeDevices >= token.maxDevicesPerAccount
}

# ---- key.roll --------------------------------------------------------------------------

findings contains {"verdict": "hold", "reason": "posture-not-ok"} if {
	input.point == "key.roll"
	facts.postureOk == false
}

# ---- key.issue -------------------------------------------------------------------------

assurance_rank := {"development": 0, "custody-bound": 1, "attested": 2}

mode_rank := {"hot": 0, "cold": 1}

custody := input.policy.factory.custody

findings contains {"verdict": "deny", "reason": "assurance-below-minimum"} if {
	input.point == "key.issue"
	assurance_rank[facts.assurance] < assurance_rank[custody.minAssurance[facts.purpose]]
}

findings contains {"verdict": "deny", "reason": "mode-below-minimum"} if {
	input.point == "key.issue"
	mode_rank[facts.mode] < mode_rank[custody.minMode[facts.purpose]]
}

findings contains {"verdict": "hold", "reason": "custodian-threshold-pending"} if {
	input.point == "key.issue"
	facts.mode == "cold"
	facts.purpose in {"root", "publisher"}
	facts.thresholdMet == false
}

# ---- bundle.release --------------------------------------------------------------------

factory := input.policy.factory

findings contains {"verdict": "deny", "reason": "tenancy-not-registered"} if {
	input.point == "bundle.release"
	factory.requireRegisteredTenancy
	facts.tenancyRegistered == false
}

# INV-10: bundles with rosters are never released to unattested keys.
findings contains {"verdict": "deny", "reason": "unattested-key-roster"} if {
	input.point == "bundle.release"
	facts.containsRoster
	facts.keyAttested == false
	not facts.unattestedAllowed
}

# REG-017: the non-production allowance releases with a flag, never silently.
findings contains {"verdict": "flag", "reason": "unattested-key-roster-development-allowance"} if {
	input.point == "bundle.release"
	facts.containsRoster
	facts.keyAttested == false
	facts.unattestedAllowed
}

findings contains {"verdict": "hold", "reason": "cohort-tenancy-limit"} if {
	input.point == "bundle.release"
	facts.activeTenanciesInCohort >= factory.maxActiveTenanciesPerCohort
}

findings contains {"verdict": "hold", "reason": "release-paused"} if {
	input.point == "bundle.release"
	facts.paused
}

# ---- posture.recheck -------------------------------------------------------------------

att := factory.attestation

posture_failures contains "verified-boot-failed" if {
	att.requireVerifiedBoot
	facts.verifiedBoot == false
}

posture_failures contains "bootloader-unlocked" if {
	att.requireBootloaderLocked
	facts.bootloaderLocked == false
}

posture_failures contains "security-level-too-low" if {
	levels[facts.securityLevel] < levels[att.minSecurityLevel]
}

# Dates are YYYY-MM-DD, so string order is date order.
posture_failures contains "os-patch-level-too-old" if {
	att.minOsPatchLevel
	facts.osPatchLevel < att.minOsPatchLevel
}

findings contains {"verdict": "flag", "reason": reason} if {
	input.point == "posture.recheck"
	some reason in posture_failures
}

findings contains {"verdict": "flag", "reason": "unknown-restriction"} if {
	input.point == "posture.recheck"
	facts.unknownRestriction
	factory.posture.unknownRestriction == "flag"
}

obligations contains "pause-release" if {
	input.point == "posture.recheck"
	count(posture_failures) > 0
	factory.posture.onFailure == "pause-release"
}

# ---- artefact.publish ------------------------------------------------------------------

pub := input.policy.publishing

kind := pub.kinds[facts.kind]

findings contains {"verdict": "deny", "reason": "author-approval-not-allowed"} if {
	input.point == "artefact.publish"
	facts.authorIsApprover
	pub.authorMayApprove == false
}

findings contains {"verdict": "deny", "reason": "insufficient-approvals"} if {
	input.point == "artefact.publish"
	facts.approvals < kind.requiredApprovals
}

findings contains {"verdict": "deny", "reason": "insufficient-publisher-signatures"} if {
	input.point == "artefact.publish"
	facts.publisherSignatures < kind.publisherThresholdM
}

findings contains {"verdict": "deny", "reason": "builder-not-allowed"} if {
	input.point == "artefact.publish"
	not facts.builder in pub.allowedBuilders
}

findings contains {"verdict": "deny", "reason": "source-not-allowed"} if {
	input.point == "artefact.publish"
	not facts.source in pub.allowedSources
}

findings contains {"verdict": "deny", "reason": "no-inclusion-proof"} if {
	input.point == "artefact.publish"
	pub.requireTransparencyLog
	facts.inclusionProof == false
}

findings contains {"verdict": "deny", "reason": "insufficient-witness-cosignatures"} if {
	input.point == "artefact.publish"
	facts.witnessCosignatures < pub.requiredWitnessCosignatures
}

# ---- intake.accept ---------------------------------------------------------------------

intake := input.policy.intake

findings contains {"verdict": "deny", "reason": "submission-too-large"} if {
	input.point == "intake.accept"
	facts.sizeBytes > intake.maxSubmissionSize
}

findings contains {"verdict": "flag", "reason": "data-quality-failure"} if {
	input.point == "intake.accept"
	facts.qualityFailures > 0
}

obligations contains "quarantine" if {
	input.point == "intake.accept"
	facts.qualityFailures > 0
	intake.dataQualityOnFailure == "quarantine"
}

# ---- consent.decide --------------------------------------------------------------------

consent := intake.consent

heuristic_hit if {
	some hit in facts.heuristicHits
	hit in consent.heuristics
}

findings contains {"verdict": "hold", "reason": "heuristic-hit"} if {
	input.point == "consent.decide"
	heuristic_hit
}

findings contains {"verdict": "hold", "reason": "evidence-needs-review"} if {
	input.point == "consent.decide"
	facts.hasEvidence
	consent.autoAcceptWithEvidence == false
}

obligations contains "sample-for-review" if {
	input.point == "consent.decide"
	facts.hasEvidence
	consent.autoAcceptWithEvidence
	not heuristic_hit
	to_number(facts.sampleDraw) < to_number(consent.sampleRate)
}

findings contains {"verdict": "hold", "reason": "no-evidence"} if {
	input.point == "consent.decide"
	facts.hasEvidence == false
	consent.withoutEvidence == "review"
}

findings contains {"verdict": "deny", "reason": "no-evidence-denied"} if {
	input.point == "consent.decide"
	facts.hasEvidence == false
	consent.withoutEvidence == "deny"
}

# ---- tenancy.late ----------------------------------------------------------------------

escalated(setting) := "deny" if setting == "deny"

escalated(setting) := "flag" if setting != "deny"

findings contains {"verdict": escalated(intake.fastRunning), "reason": "clock-running-fast"} if {
	input.point == "tenancy.late"
	facts.fastRunning
}

findings contains {"verdict": escalated(intake.provablyLate), "reason": "provably-late"} if {
	input.point == "tenancy.late"
	facts.lateSeconds > intake.timeGrace
	facts.provablyLate
}

findings contains {"verdict": "flag", "reason": "late-beyond-grace"} if {
	input.point == "tenancy.late"
	facts.lateSeconds > intake.timeGrace
	facts.provablyLate == false
}

# ---- the decision ----------------------------------------------------------------------

default verdict := "allow"

verdict := name if {
	count(findings) > 0
	strongest := max({rank[f.verdict] | some f in findings})
	some name, r in rank
	r == strongest
}

decision := {
	"verdict": verdict,
	"reasons": sort([f.reason | some f in findings]),
	"obligations": sort([o | some o in obligations]),
}
