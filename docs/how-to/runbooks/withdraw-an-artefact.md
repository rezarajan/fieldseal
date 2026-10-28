# Withdraw an artefact

A published artefact can't be changed or deleted, but it can be withdrawn: the publisher threshold signs a withdrawal over its content address, the withdrawal is logged, and from then on the factory won't build bundles with it and runtimes refuse to start new records against it (PUB-080 to PUB-083). The rules are in the [Publishing spec](../../reference/spec/publishing.md), and the short version is in [Set up publishing signatures](../set-up-publishing-signatures.md) section 5.

Records already made against the artefact stay valid. Devices may still review, export and clear them, and intake lands records made before the withdrawal reached the device (PUB-082, PUB-083).

## When

- The artefact has an error that would corrupt data or mislead people.
- It exposes something it shouldn't, or was published by mistake.
- It is replaced by a correction that devices must not mix with the old one.

If a key was compromised, run [Emergency revocation](./emergency-revocation.md) first.

## Before you start

- [ ] The content address (fingerprint) of the artefact to withdraw, taken from the registry, not from memory.
- [ ] A reason, written without personal data: it is logged.
- [ ] The **publisher threshold** is available: at least `m` publishers with their tokens.
- [ ] If a correction is ready, it is reviewed and ready to publish next ([Publish an instrument](./publish-an-instrument.md)).

## Steps

1. **Confirm the target.** Check the address resolves to the artefact you mean and see where it is used:

   ```sh
   fieldseal log prove <address>
   ```

   A proof shows it is logged; the registry's listing tells you which bundles and tenancies use it.
2. **Agree the reason** with the incident lead and the publishers. Write it in the log.
3. **Sign and log the withdrawal.** Each publisher needed for the threshold runs the command on their own machine with `FIELDSEAL_SIGNER` set to their own token:

   ```sh
   fieldseal artefact withdraw <address> --reason "<reason>"
   ```

   The withdrawal must be signed by the publisher threshold for the artefact's kind, over its own tag, and logged before it reaches the registry (PUB-080, PUB-050).
4. **Check it was logged:**

   ```sh
   fieldseal log prove <address>
   fieldseal artefact verify <publication-file>
   ```

   `artefact verify` should now report the publication as withdrawn.
5. **Check the factory has stopped.** Build or rebuild a test bundle for a non-production tenancy and confirm it doesn't include the artefact:

   ```sh
   fieldseal bundle build --tenancy <test-tenancy-id> --instrument <address> --roster <roster-file>
   ```

   Expect a refusal. The factory builds only from publications that aren't withdrawn (PUB-070, PUB-081).
6. **Publish the correction**, if there is one, and let new bundles carry it.
7. **Tell the field.** Withdrawals reach runtimes inside bundles (PUB-082), so devices that don't sync won't learn of it until they do. Contact the operators of those deployments and give them the address and the instruction to stop collecting with it.
8. **Record** the address, reason, signers, log proof and the date the factory stopped.

## Checklist

- [ ] Address copied from the registry and double-checked by a second person
- [ ] Reason has no personal data
- [ ] The threshold's worth of publishers signed
- [ ] Withdrawal logged; `log prove` returns a proof
- [ ] The factory refuses to build bundles with the artefact
- [ ] Correction published, if needed
- [ ] Field operators told; offline devices will learn of it at their next bundle

## Failure handling

| What happened | Do |
|---|---|
| `artefact withdraw` exits `4` | The address wasn't found in the registry. Re-copy it; don't guess. |
| `artefact withdraw` exits `5` | A policy denied it, for example the signer isn't a listed publisher for this kind (PUB-040). Use a listed publisher. |
| Fewer than the threshold's publishers available | The withdrawal won't take effect. Find another publisher; don't lower the threshold. If a key was lost, use [Onboard or offboard a publisher](./onboard-or-offboard-a-publisher.md). |
| The CLI doesn't say how a second publisher's signature joins the first | The CLI spec lists only `artefact withdraw <address> --reason`. Run it for each publisher and confirm with `log prove` and `artefact verify` that the withdrawal is logged. If it isn't, escalate; don't improvise a manual log entry. |
| `artefact withdraw` exits `3` | The log or registry isn't reachable. Repeat when it is; nothing is half-logged (CLI-006). |
| The factory still builds bundles with it | The registry hasn't picked up the withdrawal. Re-check with `artefact verify`; escalate before building anything for the field. |
| Records were made against it after you decided to withdraw | They are valid. Intake lands records made before the withdrawal reached the device and flags the rest (PUB-083). Tell the data team. |
| The wrong artefact was withdrawn | Withdrawal can't be undone. Publish the artefact again as new content with a change that makes its address different, after review. |
