# ADR 0002: Name the system Fieldseal

**Status:** Accepted (2026-10-26, architecture review #40) · **Priority:** Must · **Date:** 2026-10-26

**In one line:** Name the system Fieldseal; resources use `apiVersion: fieldseal.dev/v1alpha1`; no programme names in specs or code.

*The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.*

## Context

The system is no longer one programme's app: it collects any instrument, for any authority, on several operating systems. It needs a neutral name, usable as an API group in resource files.

## Decision

- The system MUST be named **Fieldseal**, with components **Factory**, **Collect** (the runtime), **Intake**, **Publish** and the **`fieldseal` CLI**.
- Resource files MUST use `apiVersion: fieldseal.dev/<version>` and a `kind`; the first version MUST be `v1alpha1`.
- Programme, organisation and subject-area names MUST NOT appear in Fieldseal's specs, code, package names or resource kinds; they belong in a deployment's own documentation.
- The `fieldseal.dev` domain SHOULD be registered before `v1`, or the group renamed.

## Consequences

- The domain `fieldseal.dev` must be registered, or the group renamed before `v1`, so the group stays unambiguous.

## Specs

[spec index](../../reference/spec/README.md)
