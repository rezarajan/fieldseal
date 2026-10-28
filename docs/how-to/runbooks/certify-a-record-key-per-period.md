# Certify a record key for a collection period

Every collection period has its own X25519 record key. Intake uses it to decrypt what devices sealed during that period (TRU-020 to TRU-023). This runbook creates one before the period starts and keeps it alive as long as its data can arrive. The rules are in the [Trust spec](../../reference/spec/trust.md); the context is in [Set up an authority's trust hierarchy](../set-up-the-trust-hierarchy.md).

**Never destroy a record key while sealed data for its period may still arrive or be held (TRU-023).** Losing a record key makes that period's data unreadable for good.

## When

- At least a few weeks before each new collection period begins, so tenancy certificates, bundles and device provisioning can name it.
- Retire it only after the retention period ends.

## Before you start

- [ ] The period ID (for example `2026-27`), its dates, and the deployment's retention period.
- [ ] Two custodians, a witness and an operator.
- [ ] The online key custody is reachable by intake only for this key (TRU-022).

## Steps

1. **Generate the record key in the key custody** that intake uses, non-exportable (TRU-013). Export only a CSR with the public key. An X25519 key can't sign, so its CSR carries no signature; its possession is proved when it first opens something sealed to it (TRU-016).
2. **Certify it at the root** with two custodians present. The validity is the period plus the retention period:

   ```sh
   fieldseal trust issue --purpose record --period <period-id> --validity <period plus retention, in days> --csr csr/record-<period-id>.csr --out certs/
   ```

3. **Check the certificate**: purpose `record`, the right period ID, the right validity, the right key ID. A second person confirms.
4. **Build and verify the trust bundle** with the new certificate added:

   ```sh
   fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
     --runtime-builds builds.yaml --out trust-bundle.yaml
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal trust verify certs/record-<period-id>.crt
   ```

5. **Publish the bundle** ([Publish an instrument](./publish-an-instrument.md) steps 4 to 9 with the bundle as the artefact).
6. **Install the certificate** beside the key in the custody and configure intake with the new period.
7. **Prove the round trip before the period opens.** In a non-production environment, run a simulated device through to intake so a record sealed to the new key is opened by intake:

   ```sh
   fieldseal device simulate --script <script-file>
   fieldseal intake run <export-file>
   ```

   A successful run shows the record key works. (For a real tenancy, `registration approve` then names this period in the tenancy certificate, TRU-021.)
8. **Record the retention date** and set a reminder at the end of retention. At that date, decide in writing whether to destroy the key; don't destroy it quietly.

## Checklist

- [ ] Key generated in custody, usable only by intake
- [ ] Certificate period ID and validity (period + retention) checked by a second person
- [ ] Bundle published; `trust verify` passes
- [ ] Round trip through `device simulate` and `intake run` succeeded
- [ ] Backup of the custody key set up according to the custody's own procedure
- [ ] Retention end date and destruction decision recorded

## Failure handling

| What happened | Do |
|---|---|
| `trust issue` exits `1` | A check failed (an identity field, wrong purpose, validity over the maximum). Fix the CSR or the request and run again. |
| `trust issue` exits `4` | The CSR file wasn't found at that path. Check `--csr`. |
| `trust verify` exits `1` | The bundle doesn't list the certificate, or the period ID is wrong. Rebuild the bundle; if the period ID is wrong, issue again with the right one and discard the wrong certificate. |
| `intake run` can't open the simulated record | The wrong key is installed or the period doesn't match. Compare the key ID in the certificate with the key in custody. Don't open the period until it passes. |
| A period's key is lost or damaged | Data sealed to it can't be read. Restore it from the custody backup. If there's no backup, tell the authority; the data is lost and devices still holding it must re-collect where possible. |
| The key is suspected compromised | Go to [Emergency revocation](./emergency-revocation.md). Sealed data stays encrypted to the old key; plan the response with the incident lead. |
