# Onboard or offboard a publisher

A publisher is a person with a personal hardware-token key that counts toward the publishing threshold. This runbook adds or removes one. It covers PUB-040 to PUB-043 in the [Publishing spec](../../reference/spec/publishing.md) and TRU-090 to TRU-094 in the [Trust spec](../../reference/spec/trust.md); the background is in [Set up publishing signatures](../set-up-publishing-signatures.md) section 1.

The rule that matters: **one person holds one publisher key** (PUB-043), and the mapping from key to person stays in the private key-holder registry, never in a certificate, bundle or log (TRU-092, TRU-094).

## Onboard a publisher

### Before you start

- [ ] The new publisher's role is approved in writing by the authority.
- [ ] There is a root ceremony or a short certification session scheduled (two custodians, a witness).
- [ ] Their hardware token is new, a PIV-capable smart card or security key that can generate and keep a P-256 key.
- [ ] The group stays at **n >= 3** for a 2-of-3 threshold.

### Steps

1. **Generate the key on the token**, by the future publisher themselves, with a PIN they choose, and touch required for each signature if the token supports it. The key never leaves the token.
2. **Export only a CSR.** No name, email or organisation (TRU-091).
3. **Record the holder** in the private key-holder registry: key ID to person, who approved, date. Access to the registry is limited (TRU-092).
4. **Certify the key** at the root, with two custodians present:

   ```sh
   fieldseal trust issue --purpose publisher --validity 730d --csr csr/publisher-<n>.csr --out certs/
   ```

5. **Check the certificate**: purpose `publisher`, validity at most 2 years, the key ID the registry lists. A second person confirms.
6. **Build the new trust bundle** with the new certificate in the publisher list:

   ```sh
   fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
     --runtime-builds builds.yaml --out trust-bundle.yaml
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal trust verify certs/publisher-<n>.crt
   ```

7. **Publish the bundle** ([Publish an instrument](./publish-an-instrument.md) steps 4 to 9, with the bundle as the artefact).
8. **Test their key** on a non-production artefact: the new publisher signs it with `FIELDSEAL_SIGNER` set to their token, and another publisher signs it too, so they exercise the threshold.

   ```sh
   fieldseal artefact sign <test-publication-file>
   fieldseal artefact verify <test-publication-file>
   ```

### Checklist (onboarding)

- [ ] Key generated on the token; CSR has no identity
- [ ] Holder recorded in the private registry only
- [ ] Certificate checked; validity at most 2 years
- [ ] New bundle published; `trust verify` passes
- [ ] A test signature verified
- [ ] Group size still meets n (at least 3 for 2-of-3)
- [ ] Rotation reminder set for 2 years minus a margin

## Offboard a publisher

Do this **the same day** the person leaves, changes role, or loses their token.

### Steps

1. **Collect the token** if you can, and disable it. This is containment, not revocation.
2. **Check the group size.** Revoking must leave at least `m` publishers (the threshold), and ideally still `n`. If it won't, start onboarding a replacement first, in parallel.
3. **Find the key ID** in the private registry.
4. **Revoke the certificate** with two custodians:

   ```sh
   fieldseal trust revoke certs/publisher-<n>.crt --reason "publisher left" --effective <time>
   ```

   For a routine leaver, the effective time is their last day. If you suspect misuse, follow [Emergency revocation](./emergency-revocation.md) and choose the effective time accordingly.
5. **Rebuild and publish the bundle** with the revocation:

   ```sh
   fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
     --runtime-builds builds.yaml --out trust-bundle.yaml
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal trust verify certs/publisher-<n>.crt     # expect exit 1
   ```

   Then publish it ([Publish an instrument](./publish-an-instrument.md) steps 4 to 9).
6. **Review what they signed** after the effective time (see [Respond to a suspected compromise](./respond-to-a-suspected-compromise.md)). Nothing should exist.
7. **Update the registry**: mark the key revoked, with the date. Don't delete the history.
8. **Release the provisioning** with the new bundle:

   ```sh
   fieldseal deployment render deployment.yaml --environment <environment>
   ```

### Checklist (offboarding)

- [ ] Token collected or disabled
- [ ] Remaining publishers still meet the threshold
- [ ] Certificate revoked by the root; `trust verify` now exits 1
- [ ] New bundle published and released to devices
- [ ] Signatures after the effective time reviewed
- [ ] Registry updated

## Failure handling

| What happened | Do |
|---|---|
| `trust issue` exits `1` | The CSR failed: identity fields, a missing proof of possession (TRU-016), or validity over 2 years. Have the publisher regenerate it on the token. |
| The same person asks for a second publisher key | Refuse. A verifier with the registry counts distinct holders and would refuse a publication met by two keys of one person (PUB-043). |
| A token is lost or broken | Treat it as offboarding that key, then onboard a replacement on a new token. If it may have been stolen, use [Emergency revocation](./emergency-revocation.md). |
| `trust revoke` exits non-zero | See [Emergency revocation](./emergency-revocation.md) failure handling. The person's access is not revoked until the bundle is published. |
| After revocation fewer than `m` publishers can sign | Publishing stops. Onboard replacements urgently; don't lower the threshold (policy only tightens). |
| `trust verify` still passes for a revoked certificate | The bundle was built from old inputs. Rebuild before publishing. |
