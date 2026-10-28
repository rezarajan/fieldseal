# Rotate a purpose key

This runbook replaces an online purpose key (`factory`, `registration`, `builder`, `receipt`, `receiver` or `publisher`) before it expires, without breaking anything signed with the old one. It follows the maintenance table in [Set up an authority's trust hierarchy](../set-up-the-trust-hierarchy.md). The rules are TRU-010 to TRU-016 in the [Trust spec](../../reference/spec/trust.md).

Rotating is **not** revoking. Signatures made inside the old key's validity stay valid (TRU-015). If the key is compromised, use [Emergency revocation](./emergency-revocation.md) instead.

Record keys follow their own runbook: [Certify a record key for a collection period](./certify-a-record-key-per-period.md).

## When

- At 80% of the key's validity (factory, registration, builder, receipt and receiver keys last at most 1 year; publisher keys at most 2).
- When moving the key to new custody (a new HSM or KMS).
- When the holder of a publisher key changes token.

## Before you start

- [ ] Two custodians available to unlock the root, plus a witness and an operator.
- [ ] The online key custody is reachable, with use logging on.
- [ ] You know which key ID is being replaced and where it is used (which component, which environment).
- [ ] The current trust bundle and its content address are to hand.

## Steps

1. **Generate the successor** in the online key custody. It must be non-exportable (TRU-013). The operator exports only a CSR with the public key and, for a P-256 key, its signature over the request (TRU-016). No names or emails (TRU-091).
2. **Take the CSR to the root.** Copy it onto removable media and carry it to the offline machine or HSM. Verify the media's contents against the CSR hash the operator read aloud.
3. **Certify it** with two custodians present, for the same purpose and a fresh validity within the maximum:

   ```sh
   fieldseal trust issue --purpose <purpose> --validity 365d --csr csr/<purpose>-next.csr --out certs/
   ```

4. **Check the certificate** before it leaves: purpose, validity and key ID against the plan. Another person than the one who ran the command checks.
5. **Build the new trust bundle** with both the old and new certificates listed, so devices and components that haven't updated still verify the old key's signatures:

   ```sh
   fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
     --runtime-builds builds.yaml --out trust-bundle.yaml
   ```

6. **Verify the new chain** as a device would:

   ```sh
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal trust verify certs/<purpose>-next.crt
   fieldseal trust verify certs/<purpose>-old.crt
   ```

7. **Publish the bundle** through the publishing flow ([Publish an instrument](./publish-an-instrument.md) steps 4 to 9, with the bundle as the artefact).
8. **Roll out the new bundle**: re-render the deployment's provisioning configuration and release it.

   ```sh
   fieldseal deployment validate deployment.yaml
   fieldseal deployment render deployment.yaml --environment <environment>
   ```

9. **Switch the component to the new key**: load the certificate beside the new key in the custody and point the component's `FIELDSEAL_SIGNER` (or equivalent configuration) at it. Do this only after the new bundle is published.
10. **Confirm** a fresh signature from the new key verifies, for example a bundle built after the switch:

    ```sh
    fieldseal bundle verify <bundle-file>
    ```

11. **Retire the old key** after its last signature can no longer be needed: disable it in custody; keep the certificate in the bundle until the old validity ends, as long as signatures made with it must still verify (TRU-015, TRU-012). Don't destroy a key in custody until you are sure nothing sealed to it can still arrive.
12. **Log it**: date, old and new key IDs, bundle content address, who was present.

## Checklist

- [ ] New key generated in custody, non-exportable, CSR carries no identity
- [ ] Certificate checked for purpose and validity by a second person
- [ ] New bundle lists both certificates; `trust verify` passes for both
- [ ] Bundle published with provenance and a log entry
- [ ] Deployment provisioning re-rendered and released
- [ ] Component switched only after the bundle was published
- [ ] Old key disabled; its certificate kept until its validity ends
- [ ] Next rotation reminder set at 80% of the new validity

## Failure handling

| What happened | Do |
|---|---|
| `trust issue` exits `1` | The CSR failed (identity field, missing signature, validity over the maximum). Regenerate the CSR with a shorter validity or without identity fields; don't edit the CSR by hand. |
| `trust issue` exits `3` | The offline signer isn't reachable. Check the quorum and the signer reference; nothing was issued. |
| `trust verify` exits `1` for the new certificate | The bundle doesn't include it, or the purpose is wrong. Rebuild the bundle with `--pins` pointing at the right directory. Don't release the bundle. |
| `trust verify` exits `1` for the **old** certificate | The new bundle dropped it. Rebuild with both certificates, or old signatures will stop verifying. |
| New bundle published but a component fails after the switch | Switch the component back to the old key (still valid and in the bundle), read the component's error, fix, and switch again. The old key stays usable until you disable it. |
| `artefact publish` fails | See [Publish an instrument](./publish-an-instrument.md) failure handling. Don't switch components until the bundle is logged. |
| The old key is found to be compromised mid-rotation | Stop and go to [Emergency revocation](./emergency-revocation.md). |
