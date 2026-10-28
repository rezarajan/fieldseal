# Deployment runbooks

Step-by-step procedures for the operations an authority repeats over a deployment's life. Each one is a checklist you can follow with the right people in the room, with what to do when a step fails. The two set-up guides explain the design; these are the scripts you run.

| Runbook | When |
|---|---|
| [Root key ceremony](./root-key-ceremony.md) | Once per authority, and when the root nears expiry; rehearse first |
| [Rotate a purpose key](./rotate-a-purpose-key.md) | At 80% of a purpose key's validity, or when moving custody |
| [Certify a record key for a collection period](./certify-a-record-key-per-period.md) | Before every collection period |
| [Emergency revocation](./emergency-revocation.md) | A key or certificate must stop being trusted now |
| [Publish an instrument](./publish-an-instrument.md) | Each new or changed instrument |
| [Withdraw an artefact](./withdraw-an-artefact.md) | A published artefact is wrong or harmful |
| [Onboard or offboard a publisher](./onboard-or-offboard-a-publisher.md) | A person joins or leaves the publisher group |
| [Respond to a suspected compromise or an unexpected log entry](./respond-to-a-suspected-compromise.md) | An alert, a report, or a log entry nobody expected |

## Conventions

**Roles.** The runbooks use the roles from [Set up an authority's trust hierarchy](../set-up-the-trust-hierarchy.md): ceremony administrator, custodians, witness and operators, plus the publishers from [Set up publishing signatures](../set-up-publishing-signatures.md). Nobody holds two roles in one procedure.

**Commands.** Only `fieldseal` commands and flags listed in the [CLI spec](../../reference/spec/cli.md) appear. Add `--json` to any of them to keep the result in the log (CLI-003). Configuration comes from `FIELDSEAL_*` variables (CLI-002), notably `FIELDSEAL_SIGNER` for the key to sign with and `FIELDSEAL_TRUST_BUNDLE` for the bundle to verify against.

**Exit codes** (CLI-005). Every "if it fails" below starts from the code:

| Code | Meaning | First thing to check |
|---|---|---|
| `1` | Verification or validation failed | The findings the command printed; do not retry with other inputs until you understand them |
| `2` | Usage error | The command line against the CLI spec |
| `3` | Configuration or adapter error | `FIELDSEAL_*` variables, the signer or log is reachable, the right release |
| `4` | A resource was not found | The path or content address; the right registry |
| `5` | A policy denied the operation | The policy layers in force (`FIELDSEAL_POLICY`); do not weaken policy to get past it |
| `6` | Internal error | Keep the full output, stop, and report it |

**Keep a log.** For every procedure, the person running it writes the date, who was present, the exact commands run, their exit codes and the content addresses involved. For ceremonies the witness signs it.

**Never retry blindly.** A command that fails after contacting the log or the registry may have partly succeeded. Publishing and logging are idempotent (CLI-006), so re-running is safe, but read the output first.
