# Set up publishing signatures

This guide sets up everything that makes a published instrument or policy trustworthy: personal publisher keys, the CI builder identity, the transparency log and the publishing policy. It then walks through publishing one artefact. Why the flow looks like this is in [ADR 0009](../explanation/adr/0009-publishing-with-provenance.md); the rules are in the [Publishing spec](../reference/spec/publishing.md).

**You need** an authority whose trust hierarchy is set up ([Set up the trust hierarchy](./set-up-the-trust-hierarchy.md)), and a source repository for artefacts.

## The principle: no single person or system can publish alone

| Step | Who | Key | Protects against |
|---|---|---|---|
| Write | Author | None (commits SHOULD be signed) | — |
| Approve | 2 reviewers, not the author | Their repository identity | A careless or malicious author |
| Build and describe | CI, on the protected branch only | `builder` key in key custody | Changes made outside review |
| Sign | 2 of 3 publishers, each on their own hardware token | Personal `publisher` keys | A single compromised publisher |
| Log | Public transparency log | The log's own key, pinned in the trust bundle | Quiet replacement of an artefact, or different devices being shown different versions |

The thresholds are publishing policy and can be raised, never lowered below the code's floors.

## 1. Give each publisher a hardware key

Publisher keys belong to **people**, so each one lives on that person's own hardware token. Use a PIV-capable smart card or security key that can generate and keep a P-256 key on the token.

For each publisher:
1. The publisher generates the key **on their token**, with a PIN they choose, and touch required for every signature if the token supports it.
2. They export only the CSR, with **no name, email address or other identity in it**: just the public key. The factory's trust tooling rejects any CSR that carries one (TRU-091). Record who holds which key ID in the authority's private key-holder registry, not in the certificate.
3. The CSR goes to the next root ceremony and is certified for purpose `publisher` with a validity of at most 2 years:

   ```sh
   fieldseal trust issue --purpose publisher --validity 730d --csr csr/publisher-alice.csr --out certs/
   ```

   For a trial run without hardware tokens, each publisher's key can be generated in a software key directory instead: `fieldseal keys generate --purpose publisher --custody keys-alice/ --csr csr/publisher-alice.csr`. That is development custody (unattested software keys), never for a real authority.

4. The certificate is added to the trust bundle's publisher list, and the bundle is republished.

Rules that hold throughout (PUB-043):
- One person holds one publisher key. A token is never shared or lent.
- Keep at least **n = 3** publishers for a 2-of-3 threshold, so one absence doesn't stop publishing.
- When a publisher leaves, revoke their certificate and republish the trust bundle the same day.

## 2. Give CI a builder identity

The builder key signs provenance: "this artefact was built from this reviewed source revision, by this pipeline".

1. Generate the `builder` key in the online key custody and certify it at a root ceremony.
2. Allow **only** the publishing workflow, running on the **protected** default branch, to use it. Use the CI platform's workload identity (OIDC federation to the key custody), not a stored secret, so a fork, a pull request or a copied secret can't sign.
3. Protect the branch:
   - require the set number of approving reviews, and dismiss approvals when new commits arrive;
   - require status checks (`fieldseal <kind> validate` and `lint`);
   - block force-pushes.
4. Record the builder's identity and the repository in publishing policy:

```yaml
apiVersion: fieldseal.dev/v1alpha1
kind: Policy
metadata: { name: authority-publishing, version: 1.0.0 }
spec:
  schemaVersion: 1.0.0
  layer: { scope: deployment }
  publishing:
    requiredApprovals: { Instrument: 2, Policy: 2, TrustBundle: 2, Deployment: 2 }
    authorMayApprove: false
    publisherThreshold: { m: 2, n: 3 }
    allowedBuilders: [ "https://ci.example.org/builders/fieldseal-publish" ]
    allowedSources: [ "https://git.example.org/authority/artefacts" ]
    requireTransparencyLog: true
```

The first publishing policy is itself published under the code's default floors (2 approvals, 2 of 3 publishers). After that, it can only tighten.

## 3. Connect the public transparency log

Publications are logged in a public transparency log ([ADR 0030](../explanation/adr/0030-public-transparency-log.md)), Sigstore's Rekor by default, through Fieldseal's `TransparencyLog` port. The port can only ever send a hash, a signature and a pseudonymous public key, so nothing about the instrument, its authors or reviewers reaches the public record. You don't configure that; it is how the port works, and its adapters are tested for it.

1. **Pin the log in the trust bundle.** Add the log's origin and public key at the next trust-bundle update (TRU-093), so devices can verify inclusion proofs offline: `fieldseal trust bundle … --log <origin>=<public key hex>`.

   For local trials the CLI has a development log kept in files (`FIELDSEAL_ADAPTERS=files`, state in `FIELDSEAL_STATE_DIR`, default `.fieldseal/`), pinned with `--log-origin fieldseal-local-log`. It signs its own checkpoints and is never a public log. The CLI uses Rekor only when `FIELDSEAL_REKOR_URL` is set explicitly.
2. **Check the adapter passes the contract suite** before first use:

   ```sh
   fieldseal conformance run --suite transparency-log
   ```

   This runs the contract against the in-process adapters (the memory and file logs). The Rekor adapter's contract needs a mock log and runs with `cargo test -p fieldseal-adapters-rekor --test rekor`; `fieldseal conformance matrix` lists every adapter and where its contract runs.

3. **Watch the log for your keys.** A scheduled job lists every entry signed by the authority's publisher key IDs and alerts on any that isn't in the registry's list of expected publications. An unexpected entry means a publisher key is being misused.

## 4. Publish an artefact

Each command below reads its settings from flags or the environment (CLI-002). On a publisher machine:

```sh
export FIELDSEAL_ADAPTERS=files                  # keep the log and registry between commands (local trial)
export FIELDSEAL_TRUST_BUNDLE=trust-bundle.bundle
export FIELDSEAL_POLICY=authority-publishing.yaml   # the publishing policy above
export FIELDSEAL_SIGNER=soft:<key directory>        # the builder's, then each publisher's own key
```

1. **Validate and lint locally:**

   ```sh
   fieldseal instrument validate health-check.yaml
   fieldseal instrument lint health-check.yaml
   fieldseal instrument preview health-check.yaml   # check how it renders
   ```

2. **Open a pull request.** Two reviewers approve; neither is the author.
3. **CI builds on merge.** It canonicalises the instrument, generates its fixed salt, computes the fingerprint ([ADR 0027](../explanation/adr/0027-salted-instrument-fingerprints.md)), and signs provenance with the builder key:

   ```sh
   fieldseal instrument hash health-check.yaml
   fieldseal artefact provenance health-check.yaml --source "$GIT_SHA" --reviewers "$APPROVERS"   # comma-separated IDs; `id:es+fr` also marks the reviewer for those languages
   ```

   This writes `health-check.publication`, a draft that collects the publishers' signatures. A new salt is drawn for an instrument unless `--salt <hex>` is given.

4. **Two publishers sign**, each on their own machine with their own key. Before signing, each checks what they are signing: the fingerprint, the diff and the provenance.

   ```sh
   fieldseal artefact verify health-check.publication     # provenance, and the signatures so far
   fieldseal artefact sign health-check.publication       # adds this publisher's signature in place
   ```

   Pass the file between publishers. A hardware custody adapter prompts for the PIN and touch; the development custody does not.

5. **Publish:**

   ```sh
   fieldseal artefact publish health-check.publication --custody receipt-keys   # the receipt key issues the time token (PUB-072); writes health-check.published
   fieldseal log prove <fingerprint>
   ```

   `publish` refuses anything `verify` would reject (CLI-012). Publishing the same fingerprint again succeeds without a second log entry (CLI-006).

6. **Check it as a device would:**

   ```sh
   fieldseal artefact verify health-check.published --trust-bundle trust-bundle.bundle
   ```

## 5. Withdraw an artefact

If a published artefact is wrong or harmful, the publisher threshold signs a withdrawal:

```sh
fieldseal artefact withdraw <fingerprint> --reason "…"          # first publisher: writes a withdrawal draft
fieldseal artefact withdraw <fingerprint> --reason "…" --draft <fingerprint-prefix>.withdrawal   # second publisher completes it
```

The factory stops building bundles with it at once; runtimes refuse it as soon as a bundle or anchor tells them.

## Checklist

- [ ] Every publisher key is on its own hardware token, with a PIN, never shared
- [ ] At least 3 publishers for a 2-of-3 threshold
- [ ] The builder key is usable only by the publishing workflow on the protected branch, through workload identity
- [ ] Branch protection requires reviews, dismisses stale approvals and blocks force-pushes
- [ ] Certificate requests carry no names or emails; the key-ID-to-person mapping is in the private registry only
- [ ] The public log is pinned in the trust bundle, its adapter passes the contract suite, and its entries for the authority's keys are monitored
- [ ] Leavers' certificates are revoked the same day
- [ ] Keys are rotated before they expire (publisher: 2 years; builder: 1 year)

## Which test proves each checklist item

Items that are about people and platforms (hardware tokens, CI branch protection, monitoring) are operational; the guarantee the software gives in each case is tested. Tests are named after the requirement IDs they cover. `fieldseal conformance run --suite publishing` runs the vectors and contracts; the rest run under `cargo test`.

| Checklist item | Guarantee | Test |
|---|---|---|
| Publisher keys on hardware, never shared | One person's keys can't meet the threshold alone (PUB-043) | `pub_043_two_keys_held_by_one_person_do_not_meet_the_threshold` (`crates/adapters/memory/tests/publishing_assurance.rs`); unit cases in `holder_tests` of the publishing application |
| At least 3 publishers for 2-of-3 | A set below the threshold is refused; two of three publish | `pub_040_a_below_threshold_set_is_refused_and_two_signatures_publish`, `pub_040_a_duplicate_signer_is_refused` (`crates/contexts/publishing/tests/`) |
| Builder key only for the publishing workflow | A builder not in policy, and a provenance signed by a non-builder key, fail | `pub_023_a_builder_not_in_policy_fails_provenance`, `pub_032_provenance_signed_by_a_non_builder_key_is_refused`, `pub_033_provenance_from_a_disallowed_source_is_refused` |
| Branch protection (reviews, stale approvals) | An unreviewed artefact can't be published; a change after approval voids it; the author doesn't count | `pub_010_an_unreviewed_artefact_cannot_reach_a_draft_and_an_unsigned_draft_cannot_be_published`, `pub_011_a_change_after_approval_voids_it`, `pub_012_the_author_does_not_count_unless_policy_allows` |
| Anything changed after signing | No bit flip in a publication verifies | `pub_041_an_artefact_modified_after_signing_fails_everywhere` |
| Certificate requests carry no names or emails | A CSR naming a person is refused; a reviewer named by email is refused | `conformance run --suite trust` (`requests/identity_rejected`, TRU-091), `pub_107_reviewers_named_by_email_are_refused`, `pub_108_provenance_naming_a_reviewer_by_email_fails_acceptance` |
| The log leaks nothing | A log entry has four fields and can't be built with a name; an adapter that transmits a label fails the contract | compile-fail doctests on `LogEntry`; `pub_104_a_log_append_transmits_exactly_four_fields_and_nothing_names_the_artefact`; `pub_104_the_contract_fails_an_adapter_that_transmits_a_label`; `conformance run --suite transparency-log` |
| The public log is pinned and its adapter passes the contract suite | A checkpoint from an unpinned log, or from the pinned origin under another key, fails | `pub_106_a_checkpoint_from_an_unpinned_log_fails`, `pub_106_a_tampered_checkpoint_is_refused`; `pub_104_rekor_passes_the_transparency_log_contract` |
| Leavers' certificates are revoked | A publisher revoked before signing is refused | `tru_042_a_publisher_revoked_before_signing_is_refused`; `conformance run --suite trust` (chain vectors) |
| Keys are rotated before they expire | An expired certificate in a chain fails | `conformance run --suite trust` (chain vectors, TRU-012) |
| A bad artefact can be withdrawn | A withdrawn artefact is refused by verification, by the factory's bundle build and by a device | `pub_080_a_withdrawn_artefact_is_refused_by_verification`, `pub_080_a_withdrawn_artefact_is_refused_by_the_factory_and_by_a_device`, `dis_030_6_an_artefact_on_the_withdrawal_list_is_rejected` |
| Look-alike instruments can't be confused | Salted fingerprints differ for look-alikes and for the same content under two salts (ADR 0027) | `wire_185_look_alike_instruments_have_different_salted_fingerprints` |

## Further reading

- SLSA build levels and provenance; in-toto attestations.
- RFC 9162, Certificate Transparency 2.0, and the C2SP checkpoint format: how logs and proofs work.
- Sigstore Rekor documentation, for the `hashedrekord` entry type.
- NIST SP 800-57 Part 1 Rev. 5, for key lifetimes.
