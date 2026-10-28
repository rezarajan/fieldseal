# Run the root key ceremony

This runbook is the script for creating an authority's offline root: rehearsal, the real ceremony, and the aftermath. It turns [Set up an authority's trust hierarchy](../set-up-the-trust-hierarchy.md) into a procedure with a checklist and failure handling. The rules are in the [Trust spec](../../reference/spec/trust.md) (TRU-001 to TRU-004).

The root can't be recovered by rotation. Rehearse, then run the real thing from a printed copy of this page.

## Before you start

- [ ] Roles assigned in writing: 1 administrator, 3 custodians (threshold 2), 1 or more witnesses, 2 or more operators. Nobody holds two roles.
- [ ] Decided and written down: the authority's name, the root validity (at most 10 years, TRU-004), the purposes needed, and the first collection period.
- [ ] Equipment ready: HSM with M-of-N quorum, or a dedicated offline machine; the verified `fieldseal` binary; new removable media; tamper-evident bags; a safe per custodian at **different locations**; the ceremony log book; a room that can be video recorded.
- [ ] `ceremony.yaml` written, reviewed by all custodians, and its hash recorded.
- [ ] A rehearsal was completed with software keys (below) and its problems fixed.

## Part A. Rehearse with software keys

Do this at least once, on a normal workstation, with the same people and the same script. The software signer is always available and its output is marked unattested (CLI-007), so nothing from a rehearsal can pass for the real root.

1. Create a scratch directory and a throwaway software key reference:

   ```sh
   export FIELDSEAL_SIGNER=soft:./rehearsal/root.key
   ```

2. Run the real command against the real `ceremony.yaml`, with the rehearsal output directory:

   ```sh
   fieldseal trust root-init --ceremony ceremony.yaml --out rehearsal/root/
   ```

3. Issue one certificate and build a bundle, exactly as in Part B steps 7 and 8, into `rehearsal/`.
4. Verify the chain:

   ```sh
   fieldseal trust verify rehearsal/certs/factory.crt
   ```

5. Time the rehearsal, note every question people asked, and fix the script.
6. **Destroy the rehearsal output** and make sure none of it reaches the real trust bundle or any device.

If a rehearsal step exits non-zero, treat it as you would in the real ceremony (see Failure handling) and fix the cause before the real day.

## Part B. The ceremony

### 1. Open

- [ ] Room booked, recorded, and entered only by the people listed.
- [ ] Witness checks the offline machine's or HSM's seals and records the serial numbers.
- [ ] Administrator verifies the `fieldseal` binary's SHA-256 aloud; the witness compares it with the published value, computed on a different machine.
- [ ] Ceremony log opened: date, people present, equipment serials, binary hash, `ceremony.yaml` hash.

### 2. Create the root

3. On the offline machine or HSM, with `FIELDSEAL_SIGNER` set to the HSM slot or offline signer:

   ```sh
   fieldseal trust root-init --ceremony ceremony.yaml --out root/
   ```

4. Each custodian sets their own PIN or passphrase for their credential, out of sight of the others.
5. Record the exit code and the root certificate's key ID in the log.

### 3. Back up

6. HSM: back up the root's partition to a second device under the same quorum. Offline machine: the backup is the custodians' shares; no complete copy exists.
   - [ ] Each custodian seals their credential in a numbered tamper-evident bag.
   - [ ] The witness records the bag numbers; each custodian takes their bag to their own safe.

### 4. Certify the purpose keys

Operators have generated the purpose keys in the online key custody and exported only CSRs (no names, no emails, TRU-091). Two custodians unlock the root.

7. For each CSR:

   ```sh
   fieldseal trust issue --purpose factory --validity 365d --csr csr/factory.csr --out certs/
   fieldseal trust issue --purpose registration --validity 365d --csr csr/registration.csr --out certs/
   fieldseal trust issue --purpose builder --validity 365d --csr csr/builder.csr --out certs/
   fieldseal trust issue --purpose receipt --validity 365d --csr csr/receipt.csr --out certs/
   fieldseal trust issue --purpose receiver --validity 365d --csr csr/intake-1.csr --out certs/
   fieldseal trust issue --purpose record --period <period-id> --validity <period plus retention> --csr csr/record.csr --out certs/
   fieldseal trust issue --purpose publisher --validity 730d --csr csr/publisher-<n>.csr --out certs/
   ```

   - [ ] Before each certificate leaves the room, someone other than the administrator reads its purpose and validity against the plan.

### 5. Build the first trust bundle

8. Still on the offline machine:

   ```sh
   fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
     --runtime-builds builds.yaml --out trust-bundle.yaml
   ```

9. Check every chain as a device would (set the bundle first):

   ```sh
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal trust verify certs/factory.crt
   ```

### 6. Close

- [ ] Custodians re-seal their credentials.
- [ ] Witness and every participant sign the log.
- [ ] Certificates and `trust-bundle.yaml` copied out on the removable media; the media is then retired or stored.
- [ ] Offline machine powered off and re-sealed, or HSM returned to its safe.

## Part C. After the ceremony

1. Load each certificate beside its key in the online key custody.
2. Publish the trust bundle as an artefact so it gets provenance and a log entry (TRU-031): follow [Publish an instrument](./publish-an-instrument.md) steps 4 to 9, with the bundle in place of the instrument.
3. Put the trust bundle in the deployment's device provisioning configuration:

   ```sh
   fieldseal deployment validate deployment.yaml
   fieldseal deployment render deployment.yaml --environment <environment>
   ```

4. Schedule the yearly custodian check and the 80%-of-validity reminders for each purpose key.

## Failure handling

| What happened | Do |
|---|---|
| `root-init` exits `3` | The signer or HSM wasn't reachable or isn't in the right state. Nothing was made. Fix the connection and repeat; log the failed attempt. |
| `root-init` exits non-zero after creating some output | Treat the key as **not trusted**. Do not use the partial output. Wipe it and the key in the HSM partition or machine, record this in the log, and restart the ceremony from step 2. |
| A custodian forgets their PIN or loses the credential during the ceremony | Stop. Do not proceed with fewer than the plan. Re-run `root-init` with a fresh root once credentials are sorted; abandon the old root unpublished. |
| `trust issue` exits `1` | The CSR failed a check: an identity field (TRU-091), a missing or bad signature (TRU-016), or a validity over the purpose maximum (TRU-012). Reject that CSR, have the operator regenerate it, and carry on with the rest. |
| `trust issue` exits `5` | A policy denied it; check the purpose and validity against the plan. Don't change policy mid-ceremony. |
| `trust bundle` exits `1` or `4` | An input is missing or invalid. Check the paths in `--roots`, `--pins`, `--attestation-roots`, `--runtime-builds`. |
| `trust verify` exits `1` | The chain doesn't reach the root in the bundle. Do not publish. Find out which certificate is wrong and re-issue it. |
| The binary hash doesn't match | Stop. Do not run anything. Fetch the binary again on another machine, and investigate before any key is created. |
| Seals are broken or a bag is missing | Treat the equipment as compromised. Abort, replace it, and start again. |
| Anything unexpected | Stop, write down what happened and who saw it, and let the witness decide whether the ceremony continues. Restart rather than improvise. |
