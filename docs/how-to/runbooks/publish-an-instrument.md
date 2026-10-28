# Publish an instrument

This runbook takes a reviewed instrument from a merged pull request to a published, logged artefact that devices will accept. It follows section 4 of [Set up publishing signatures](../set-up-publishing-signatures.md); the rules are in the [Publishing spec](../../reference/spec/publishing.md). The same steps publish a policy, a trust bundle or a deployment manifest with that kind's `validate` command in place of the instrument's.

No one can publish alone: two reviewers who aren't the author, the builder key on the protected branch, and two of the publishers all take part (PUB-010 to PUB-012, PUB-040).

## Before you start

- [ ] The change is in a pull request; **two reviewers** who aren't the author have approved the current commit (a later commit voids earlier approvals, PUB-011).
- [ ] CI's required checks have passed.
- [ ] At least two publishers are available with their hardware tokens, and each has the PIN.
- [ ] `FIELDSEAL_TRUST_BUNDLE`, `FIELDSEAL_LOG_URL` and `FIELDSEAL_REGISTRY_URL` point at the right environment.
- [ ] The transparency log is reachable and its adapter passed the contract suite when it was set up.

## Steps

1. **Validate and lint locally**, as the author:

   ```sh
   fieldseal instrument validate health-check.yaml
   fieldseal instrument lint health-check.yaml
   fieldseal instrument preview health-check.yaml
   ```

   `validate` and `lint` exit `1` on any error finding (CLI-010).
2. **Get two approvals** in the pull request. Reviewers read the diff and the preview, not only the summary.
3. **Merge to the protected branch.** CI builds and describes the artefact with the builder key through its workload identity.
4. **Compute the fingerprint** and check it matches what CI printed (PUB-022):

   ```sh
   fieldseal instrument hash health-check.yaml
   ```

5. **Create provenance**, in CI, on the protected branch:

   ```sh
   fieldseal artefact provenance health-check.yaml --source "$GIT_SHA" --reviewers "$APPROVERS"
   ```

6. **Each publisher verifies before signing.** They check the fingerprint, the diff and the provenance against what was reviewed, and run:

   ```sh
   fieldseal artefact verify health-check.publication
   ```

   If it doesn't pass, they don't sign (PUB-042).
7. **Each of two publishers signs**, on their own machine and token, with `FIELDSEAL_SIGNER` set to their token (for example `pkcs11:slot=publisher`). The token asks for the PIN and a touch:

   ```sh
   fieldseal artefact sign health-check.publication
   ```

8. **Verify the full set**, with the threshold now met:

   ```sh
   fieldseal artefact verify health-check.publication
   ```

9. **Publish.** This appends to the log and then the registry (PUB-050). It refuses anything `verify` would reject (CLI-012):

   ```sh
   fieldseal artefact publish health-check.publication --time-token checkpoint.token   # or --custody <dir> holding the receipt key (PUB-072)
   fieldseal log prove <fingerprint>
   ```

10. **Check as a device would**, with the trust bundle a device holds:

    ```sh
    fieldseal artefact verify health-check.publication
    fieldseal log verify <proof-file>
    ```

11. **Record** the fingerprint, the log entry's address, who reviewed and who signed.

## Checklist

- [ ] Two non-author approvals on the final commit
- [ ] `validate`, `lint`, `preview` clean
- [ ] Local `hash` equals CI's fingerprint
- [ ] Two distinct publishers signed after reading the diff and provenance
- [ ] `artefact verify` passes before and after signing
- [ ] `artefact publish` succeeded and `log prove` returns a proof
- [ ] `log verify` passes against the pinned log key
- [ ] The log entry matches what the registry lists for this publication

## Failure handling

| What happened | Do |
|---|---|
| `validate` or `lint` exits `1` | Fix the findings in the instrument. Don't merge. |
| `instrument hash` differs from CI | Canonical bytes differ (PUB-022). Stop. Find out what changed between the reviewed commit and what CI built. Don't sign. |
| `artefact verify` exits `1` before signing | Reviews, provenance or validation don't pass (PUB-042). Read the findings; fix the cause (a stale approval, an unlisted builder, a wrong source) and rebuild. Don't sign around it. |
| `artefact sign` exits `3` | The token isn't found or the PIN failed. Check the reference in `FIELDSEAL_SIGNER`. After repeated PIN failures a token may lock; use another publisher. |
| `artefact sign` exits `5` | Policy denied it: perhaps the same person holds both keys (PUB-043) or the key isn't a listed publisher. Don't work around it. |
| `artefact publish` exits `3` | Log or registry not reachable. Nothing is half-logged (CLI-006). Check `FIELDSEAL_LOG_URL`, then re-run the same command; repeating a publish of the same content address succeeds without a second entry. |
| `artefact publish` exits `1` | It would not verify. Re-run `artefact verify` and read the findings. |
| `publish` succeeds but `log prove` fails | Wait and retry once. If it still fails, treat it as a log problem and tell the incident lead; do not announce the publication. |
| `log verify` exits `1` | The proof doesn't match the pinned log key or tree head. Do not release bundles built from this artefact. Go to [Respond to a suspected compromise](./respond-to-a-suspected-compromise.md). |
| You published the wrong thing | Don't edit it; content addresses are immutable (PUB-062). [Withdraw it](./withdraw-an-artefact.md) and publish a correction. |
