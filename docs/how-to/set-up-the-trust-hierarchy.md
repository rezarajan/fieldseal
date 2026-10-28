# Set up an authority's trust hierarchy

This guide creates an authority's offline root, its online purpose keys and its first trust bundle, following current key-management practice. Do it once per authority, before anything is published or registered. Why the hierarchy looks like this is in [ADR 0008](../explanation/adr/0008-trust-hierarchy.md); the normative rules are in the [Trust spec](../reference/spec/trust.md).

The root is the one key that can't be recovered by rotation: if it is lost, every device must be re-provisioned; if it is stolen, the authority's whole deployment is compromised. Everything below is about making that impossible by accident and hard on purpose.

## Before you start

**People.** Assign these roles in writing. Nobody holds two of them.

| Role | Count | Does |
|---|---|---|
| Ceremony administrator | 1 | Runs the script, operates the offline machine |
| Custodians | 3 (threshold 2) | Each holds one root credential or backup share; at least 2 are needed for any root operation (TRU-002) |
| Witness | 1 or more | Watches every step, signs the ceremony record; not a custodian |
| Operators | 2 or more | Hold access to the online key custody (HSM or KMS) for purpose keys |

**Equipment.**
- **For the root**, either an HSM, ideally FIPS 140-3 Level 3, configured for M-of-N quorum authentication, or a dedicated **offline machine**: never networked, wireless removed or disabled, booted from read-only media.
- **The `fieldseal` binary**, verified before use: its SHA-256 and signature checked against the release, on a different machine.
- **Removable media** for moving signing requests in and certificates out. New, write-once where possible, used only for this.
- **Tamper-evident bags**, a safe for each custodian in a **different location**, a printed copy of this script, and a ceremony log book.
- **Online key custody** for purpose keys: an HSM or a cloud KMS whose keys are non-exportable (TRU-013), with use logging turned on.

**Decide in advance:** the authority's name for its root, the root's validity (at most 10 years, TRU-004), the purposes you need (see the table in step 4), and the first collection period.

## 1. Prepare the ceremony

1. Book a room where the session can be recorded on video, and nobody can enter unobserved.
2. The witness checks that the offline machine's seals are intact and records their serial numbers.
3. The administrator verifies the `fieldseal` binary's hash aloud; the witness compares it with the published value.
4. Start the ceremony log: date, people present, equipment serial numbers, binary hash.

## 2. Create the root

On the offline machine or HSM:

```sh
fieldseal trust root-init --ceremony ceremony.yaml --out root/
```

`ceremony.yaml` names the authority, the root's validity, the custodian threshold (`2-of-3`), the custodians and the witnesses (a witness is not a custodian):

```yaml
authority: example-authority
threshold: 2-of-3
custodians: [custodian-a, custodian-b, custodian-c]
witnesses: [witness-1]
held: 2026-01-15T08:00:00Z      # defaults to now
validity: 3650d                 # or notAfter: <time>; at most 10 years
```

The command:
- generates the P-256 root key **inside** the HSM or offline machine; it never leaves;
- creates each custodian's credential: an HSM quorum card, or an encrypted backup share when using an offline machine;
- writes the root certificate and a **signed ceremony record** (TRU-002).

Each custodian sets their own PIN or passphrase for their credential, out of sight of the others.

> **Development custody.** The `fieldseal` binary signs with a *software* key directory (`--out root/` becomes the root's key directory; `FIELDSEAL_SIGNER=soft:root/` points later commands at it). That is for development, tests and practice ceremonies only: the key is a file, the custodian threshold is recorded but the key is not split, and every key is unattested (CLI-007). A production authority uses an HSM adapter for the same `KeyCustody` port, and these commands do not change. Every command that uses the development custody says so in its output.

## 3. Back up the root

- **With an HSM:** create a backup of the root's partition to a second HSM or backup device, under the same quorum. Store it at a third site.
- **With an offline machine:** the backup is the custodians' shares; any 2 of 3 reconstruct the key. No complete copy exists anywhere.

Each custodian seals their credential in a numbered tamper-evident bag. The witness records the bag numbers in the log, and each custodian takes their bag to their own safe.

**Never:** photograph a credential, store two shares in one place, keep a share on a networked machine, or let one person hold 2 shares.

## 4. Create the purpose keys

Each online purpose key is **generated in the online key custody**, never on the offline machine and never exported. For each purpose:

| Purpose | Used by | Validity (maximum) |
|---|---|---|
| `factory` | The factory, to sign bundles | 1 year |
| `registration` | The factory, for tokens and certificates | 1 year |
| `builder` | CI, to sign provenance ([Set up publishing signatures](./set-up-publishing-signatures.md)) | 1 year |
| `receipt` | Intake, for receipts and time tokens | 1 year |
| `receiver` | Each intake host, to prove it may receive uploads | 1 year |
| `record` | Intake, one per collection period, to decrypt records | The period plus retention |

Publisher keys are personal and are created separately, on each publisher's own hardware token ([Set up publishing signatures](./set-up-publishing-signatures.md)).

1. An operator generates the key in the key custody and exports **only** a certificate signing request (CSR) for it. With the development custody: `fieldseal keys generate --purpose factory --custody online/ --csr csr/factory.csr` (`--algorithm x25519` for a `registration` sealing key; `record` keys are X25519). The CSR carries the public key and, for a P-256 key, the key's own signature over the request, proving custody holds it (TRU-016); nothing else: no names, email addresses or organisation fields. `fieldseal trust issue` rejects any CSR with identity fields (TRU-091), and any P-256 CSR without a valid signature.
2. Copy all CSRs onto the removable media.

## 5. Certify the purpose keys with the root

Back on the offline machine, with 2 custodians present to unlock the root:

```sh
export FIELDSEAL_SIGNER=soft:root/      # the offline signer (or --custody root/)
fieldseal trust issue --purpose factory  --validity 365d --csr csr/factory.csr  --out certs/
fieldseal trust issue --purpose receiver --validity 365d --csr csr/intake-1.csr --out certs/
fieldseal trust issue --purpose record   --period 2026-27 --period-start 2026-09-01 --period-end 2027-07-31 \
  --retention 180d --csr csr/record-2026-27.csr --out certs/
# …one per CSR
```

Each certificate is written to `--out` under the request's file name (`certs/factory.crt`). `--at <time>` sets the issue time (default: now). A `record` key's validity is the period plus the retention, so it takes the period's dates instead of `--validity`.

The root signs only key certificates, trust bundles and revocations (TRU-003). Check each certificate's purpose and validity before it leaves the room.

## 6. Build the first trust bundle

Still on the offline machine:

```sh
fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
  --runtime-builds builds.yaml --log-origin fieldseal-local-log --out trust-bundle.bundle
```

The bundle lists the root, the purpose-key certificates, the platform attestation roots (one file per evidence format, named for it), the runtime builds the authority accepts (TRU-030), and the transparency log's origin and key (TRU-093). The root signs it. The flags beyond the required ones are optional:

- `builds.yaml` is a list of `{platform, appId, signingDigests: [<sha-256 hex>]}`.
- `--log-origin <origin>` pins the local development log of that name; `--log <origin>=<public key hex>` pins any other log (for example the public one). Repeat either.
- `--publishers <file>` maps artefact kinds to the key IDs allowed to publish them; by default every `publisher` certificate in `--pins` is allowed for every kind.
- `--revocations <dir>` includes root revocations; `--previous <bundle>` checks that components holding it will accept the new one (TRU-033) and numbers it one patch higher; `--name` and `--version` set the bundle's name and version.

The bundle is canonical CBOR, whatever its file name.

Close the ceremony:
1. The custodians re-seal their credentials.
2. The witness and every participant sign the log.
3. Copy the certificates and trust bundle out on the removable media.

## 7. Install and publish

1. Load each certificate next to its key in the online key custody.
2. Publish the trust bundle as an artefact through the publishing flow, so it gets provenance and a log entry (TRU-031).
3. Put the trust bundle into the deployment's device provisioning configuration. Runtimes get it at provisioning, never from the app build (TRU-032).

Check every chain the way a device will:

```sh
fieldseal trust verify certs/factory.crt --trust-bundle trust-bundle.bundle
```

## Keep it healthy

| When | What |
|---|---|
| At 80% of a purpose key's validity | Generate a successor in key custody and certify it in a short ceremony (2 custodians). Old signatures stay valid (TRU-015). |
| Each new collection period | Certify a new `record` key. **Never destroy** a record key while sealed data for its period may still arrive (TRU-023). |
| A purpose key is suspected compromised | Revoke it with the root at once (`fieldseal trust revoke certs/factory.crt --reason compromised`, with 2 custodians), publish a new trust bundle with `--revocations`, and certify a replacement. |
| A custodian leaves | Re-share (offline machine) or re-issue the quorum card (HSM) without them, in a ceremony. |
| Every year | Check that each custodian's bag is intact and that 2 custodians can still unlock the root; record it in the log. |
| Root nearing expiry | Create a new root in a full ceremony and publish a trust bundle signed by **both** roots (TRU-004). |

## Further reading

- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management*: key lifetimes, custody and backup.
- FIPS 140-3: validation levels for HSMs.
- The IANA DNSSEC root key-signing ceremonies: a public, well-documented model for offline root ceremonies with custodians and witnesses.
