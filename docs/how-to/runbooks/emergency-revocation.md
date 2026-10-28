# Revoke a key or certificate in an emergency

Use this when a key or certificate must stop being trusted now: a stolen token, a leaked custody credential, a key used outside its purpose. The root signs a revocation, the revocation travels in the next trust bundle, and verifiers refuse signatures made at or after the key's effective revocation time (TRU-040 to TRU-042). The rules are in the [Trust spec](../../reference/spec/trust.md).

Speed matters, but so does the order. Revoke first; investigate second ([Respond to a suspected compromise](./respond-to-a-suspected-compromise.md) runs alongside).

Device keys are **not** revoked here; the factory's device registry does that (TRU-043). Receiver keys are revoked like any purpose key (TRU-082).

## Before you start

- [ ] An incident lead is named and keeps a timeline.
- [ ] Two custodians are reachable and can reach the root within hours. (If they can't, start gathering them now; the rest of the procedure waits for them.)
- [ ] You know the certificate to revoke and its key ID, from the trust bundle or the private key-holder registry.
- [ ] You have decided the **effective time**: the earliest moment you think the key could have been misused. Pick earlier rather than later. A signature made at or after this time becomes invalid (TRU-042), which may also invalidate legitimate recent signatures. That is the safe side of the trade.
- [ ] A replacement is planned (a new key through [Rotate a purpose key](./rotate-a-purpose-key.md), or a publisher through [Onboard or offboard a publisher](./onboard-or-offboard-a-publisher.md)).

## Steps

1. **Contain first.** In the online key custody, disable the affected key so it can't sign any more. For a publisher token, tell the holder to stop using it. Write down the time you did it.
2. **Gather the custodians.** Two unlock the root with a witness present, on the offline machine or HSM. Verify the `fieldseal` binary hash as in the [Root key ceremony](./root-key-ceremony.md) step 1, in shortened form.
3. **Sign the revocation.**

   ```sh
   fieldseal trust revoke certs/<certificate>.crt --reason "<short reason without personal data>" --effective <effective-time>
   ```

   The reason is free text that ends up in a published bundle; don't put names, emails or case details in it.
4. **Build a new trust bundle** carrying the revocation, and the replacement certificate if it's ready:

   ```sh
   fieldseal trust bundle --roots root/root.crt --pins certs/ --attestation-roots attestation-roots/ \
     --runtime-builds builds.yaml --out trust-bundle.yaml
   ```

5. **Check it.** The revoked certificate must now fail and the others must pass:

   ```sh
   export FIELDSEAL_TRUST_BUNDLE=trust-bundle.yaml
   fieldseal trust verify certs/<revoked>.crt     # expect exit 1
   fieldseal trust verify certs/<other>.crt       # expect exit 0
   ```

6. **Publish the bundle** at once ([Publish an instrument](./publish-an-instrument.md) steps 4 to 9, with the bundle as the artefact). If the revoked key is a publisher key, the remaining publishers must still meet the threshold; if they can't, use a break-glass: see Failure handling.
7. **Distribute.** Revocations reach devices in bundles and anchors (TRU-041). Re-render and release the deployment's provisioning configuration, and make sure the factory builds the next bundles against the new trust bundle:

   ```sh
   fieldseal deployment validate deployment.yaml
   fieldseal deployment render deployment.yaml --environment <environment>
   ```

8. **Review what the key signed** since the effective time. For a publisher or builder key, list the log entries and publications for the key ID since then (see [Respond to a suspected compromise](./respond-to-a-suspected-compromise.md)); withdraw anything that shouldn't stand ([Withdraw an artefact](./withdraw-an-artefact.md)).
9. **Replace the key** and close the incident in the log: times, content addresses, who did what.

## Checklist

- [ ] Key disabled in custody (time recorded)
- [ ] Effective time chosen and written down with the reason for choosing it
- [ ] Revocation signed by the root with two custodians present
- [ ] New bundle: revoked certificate fails `trust verify`, others pass
- [ ] Bundle published, deployment provisioning released
- [ ] Everything the key signed since the effective time reviewed
- [ ] Replacement certified; incident log closed

## Failure handling

| What happened | Do |
|---|---|
| `trust revoke` exits `3` | The offline signer isn't ready or the quorum isn't met. Nothing was signed. Fix and repeat. Keep the key disabled meanwhile. |
| `trust revoke` exits `4` | The certificate wasn't found. Take it from the current trust bundle by key ID, not from memory. |
| `trust revoke` exits `5` | A policy denied it. Don't weaken the policy; escalate to the incident lead. |
| Custodians can't be reached for hours | Keep the key disabled in custody. Components that use the key will stop working; accept that. Don't create ad hoc trust bundles or sign anything off-ceremony. |
| The revoked certificate still verifies | The bundle was built from the old inputs. Rebuild and re-check before publishing. |
| `artefact publish` of the bundle fails | See [Publish an instrument](./publish-an-instrument.md) failure handling. Until the bundle is out, the revocation isn't effective anywhere; escalate. |
| The remaining publishers can't meet the threshold | Onboard replacement publishers through a short ceremony first ([Onboard or offboard a publisher](./onboard-or-offboard-a-publisher.md)). Don't lower the threshold; policy only tightens. |
| The root itself may be compromised | This runbook doesn't cover it. Treat it as a new authority: run the [Root key ceremony](./root-key-ceremony.md) and re-provision every device. |
