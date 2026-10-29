# Fieldseal documentation

Fieldseal collects structured data about people in the field, on shared and offline devices, and delivers it to an authority by any route, with provenance from the published definition of what is collected to the record that lands. The documentation follows [Diátaxis](https://diataxis.fr/).

## Start here

- [System overview](explanation/overview.md): how the parts fit, with the architecture diagram
- [Glossary](reference/glossary.md): the terms every document uses

## Explanation: understand why

- [Architecture decision records](explanation/adr/README.md): every decision, one per file
- [How the build works, and why](explanation/build-system.md): Nix, the container, portability, reproducibility and testing layers

## Reference: look up the facts

- [Specifications](reference/spec/README.md): normative specs per bounded context, with requirement IDs
- [The survey folder](reference/survey-folder.md): which file holds each setting, translation keys and what `survey check` reports
- [Toolchain and repository](reference/toolchain.md): platforms, repository layout, tool versions, CI images

## How-to guides: get a task done

- [Build and check the project](how-to/build-and-check.md)
- [Reuse the CI images](how-to/reuse-ci-images.md)
- [Run the whole factory stack locally](how-to/run-the-local-stack.md): compose stack with a passkey-only Keycloak, the factory, the intake endpoint and the transparency log
- [Set up an authority's trust hierarchy](how-to/set-up-the-trust-hierarchy.md): root ceremony, purpose keys, trust bundle
- [Set up publishing signatures](how-to/set-up-publishing-signatures.md): publisher tokens, CI builder identity, transparency log, publishing an artefact
- [Deployment runbooks](how-to/runbooks/README.md): step-by-step procedures with checklists and failure handling
  - [Root key ceremony](how-to/runbooks/root-key-ceremony.md)
  - [Rotate a purpose key](how-to/runbooks/rotate-a-purpose-key.md)
  - [Certify a record key for a collection period](how-to/runbooks/certify-a-record-key-per-period.md)
  - [Emergency revocation](how-to/runbooks/emergency-revocation.md)
  - [Publish an instrument](how-to/runbooks/publish-an-instrument.md)
  - [Withdraw an artefact](how-to/runbooks/withdraw-an-artefact.md)
  - [Onboard or offboard a publisher](how-to/runbooks/onboard-or-offboard-a-publisher.md)
  - [Respond to a suspected compromise or unexpected log entry](how-to/runbooks/respond-to-a-suspected-compromise.md)

## Tutorials

- [Hands-on: the whole system, one step at a time](tutorials/hands-on.md)
- [Write and publish your first survey](tutorials/write-and-publish-your-first-survey.md)

## Deployment documentation

Each deployment's own documentation (its policies, instruments, trust fingerprints and runbooks) is generated from its deployment manifest by `fieldseal docs build` and ships with its release, not in this repository ([ADR 0025](explanation/adr/0025-twelve-factor-deployments.md)).

## Archive

[Superseded v0.x design documents](archive/README.md), kept for their reasoning.
