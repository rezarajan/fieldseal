# Respond to a suspected key compromise or an unexpected log entry

Use this when a custodian or publisher reports a stolen or misused credential, when a custody or CI log shows use nobody can explain, or when the transparency-log monitor shows an entry for one of the authority's keys that isn't in the registry's list of expected publications. The monitor is described in [Set up publishing signatures](../set-up-publishing-signatures.md) section 3. The rules are in the [Publishing spec](../../reference/spec/publishing.md) (PUB-050 to PUB-056, PUB-080) and the [Trust spec](../../reference/spec/trust.md) (TRU-040 to TRU-043).

An entry in a public transparency log can't be removed. What you control is whether anyone **trusts** it: you revoke the key, and withdraw what it published.

## Roles

| Role | Does |
|---|---|
| Incident lead | Decides, keeps the timeline, speaks for the authority |
| Operators | Act in the key custody and CI; collect logs |
| Custodians | Needed for any root signature (revocation, a new bundle) |
| Publishers | Needed to withdraw (threshold) |
| Registry holder | Maps key IDs to people (TRU-092); the only person who does |

## Step 1. Triage (first 30 minutes)

1. **Open the incident log.** Time, who reported, what was seen, the key ID(s) and content address(es) involved.
2. **Decide the class**, which sets the order of work:
   - **A. A credential may be in the wrong hands** (lost token, leaked custody credential, stolen laptop): go to Step 2 now.
   - **B. An unexpected log entry for one of our keys:** go to Step 3, then Step 2 if it isn't explained.
   - **C. An unexpected entry for a key that isn't ours:** this is outside our trust bundle and shouldn't verify. Record it, check Step 3 only to confirm it doesn't, and stop unless something relied on it.
3. **Don't delete evidence.** Preserve custody use logs, CI logs and the log entries as they are.

## Step 2. Contain

1. **Disable** the affected key in the online key custody or, for a publisher token, ask the holder to stop using it and collect it.
2. **Revoke** if you can't rule out misuse: follow [Emergency revocation](./emergency-revocation.md). Choose the effective time as the earliest moment the credential could have been exposed.
3. **Stop publishing** that depends on the key. If the `builder` key is involved, disable the publishing workflow.

## Step 3. Check what the log holds

For the content address (or fingerprint) of each entry you're concerned about:

1. **Fetch the proof and the signed tree head:**

   ```sh
   fieldseal log prove <address>
   ```

2. **Verify the proof** against the tree head pinned in your trust bundle:

   ```sh
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal log verify <proof-file>
   ```

   Exit `1` means the proof doesn't match the pinned log key or a known tree head. That is a different, more serious problem: the log may be showing different views. Tell the incident lead at once and don't rely on the log until you've compared tree heads with a second observer.
3. **Verify the artefact the entry points to**, if it's in the registry:

   ```sh
   fieldseal artefact verify <publication-file>
   ```

   Check the signatures against the threshold, the provenance (builder, source revision, reviewers) and the log inclusion.
4. **Compare with the expected-publications list.** Decide:
   - **Expected, just missing from the list:** record why, fix the list, close.
   - **Not expected, signed by a compromised key:** continue.
   - **Not expected, signed within the threshold by valid publishers:** it may be an insider or a social-engineering case; do not accuse anyone. Treat it as a compromise of each signing key until the holders explain.

## Step 4. Reduce the harm

1. **Withdraw** anything that shouldn't stand ([Withdraw an artefact](./withdraw-an-artefact.md)). The factory stops building with it at once (PUB-081).
2. **Find what already consumed it.** Which bundles were built since the entry appeared? Which tenancies hold them? The registry and the factory's build records tell you. Devices learn of the withdrawal at their next bundle (PUB-082).
3. **Check intake.** Records made against a withdrawn artefact before the withdrawal reached the device are valid; later ones are flagged (PUB-083). Ask the data team to look at the flags.
4. **Check unauthorised use of other purposes.** A compromised custody credential can reach more than one key. List the keys that credential could use and rotate or revoke each ([Rotate a purpose key](./rotate-a-purpose-key.md)).

## Step 5. Recover

1. **Replace the keys** and re-certify them. Publish the new trust bundle with the revocations ([Emergency revocation](./emergency-revocation.md) steps 4 to 7).
2. **Restore publishing** only when the builder identity, branch protection and the publishers' tokens have been checked.
3. **Check the monitor works.** Make a test publication on a non-production key and confirm the monitor sees it and the expected list matches.

## Step 6. Close

- [ ] Timeline complete: first sign, detection, containment, revocation, bundle published, withdrawals, recovery.
- [ ] Root cause written down; the control that should have caught it is named.
- [ ] People told: custodians, publishers, deployment operators, the authority's data protection contact if records may be affected.
- [ ] Follow-ups raised (policy, procedure, monitoring).
- [ ] Incident log signed by the incident lead and a witness.

## Failure handling

| What happened | Do |
|---|---|
| `log prove` exits `4` | The log doesn't know that address. Check the address; if it's right, the artefact was never logged and no device should accept it (PUB-050). Record that. |
| `log prove` exits `3` | The log isn't reachable. Retry; use a second observer or a mirror if there is one. Don't conclude the entry doesn't exist. |
| `log verify` exits `1` | The proof doesn't verify against the pinned tree head or log key. Escalate: this may be a log fault or a split view. Don't build or ship anything until it's understood. |
| `artefact verify` exits `1` for the suspect artefact | It doesn't meet policy: this is expected for a forgery. Withdraw it anyway if it was logged. |
| `artefact verify` passes for an artefact nobody expected | The signing keys are valid and met the threshold. Treat every signing key and the builder identity as compromised until shown otherwise. |
| The monitor didn't alert | Treat the monitor as failed. Restore alerting first, then look for other entries it may have missed since its last good run. |
| The root may be involved | Go to the root section of [Emergency revocation](./emergency-revocation.md) failure handling: this is a new-authority event. |
| You can't tell whether it was misuse | Assume it was. Revoking and replacing a key costs a short ceremony; trusting a stolen one costs the deployment. |
