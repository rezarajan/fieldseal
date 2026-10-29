# Manage rosters

A roster lists the subjects of one cohort: an ID, the name the collector sees, a consent state and the values a survey reads as `roster.<field>`. A `granted` consent covers only the surveys the roster names in `consent-covers` (see below). This guide covers the three commands that work on files and a copy of the roster store (`roster check`, `roster diff` and `roster list`) and the two operations of the factory (`roster issue` and `roster assign`).

## Check a roster against its survey

```sh
fieldseal roster check examples/rosters/village-a.yaml \
  --instrument examples/surveys/household-water-access
```

The command checks the file first, then compares it with the survey.

- The file must be a closed form: one cohort, a `version` of at least 1, unique subject IDs, a consent state of `granted`, `refused` or `unknown`, and no key that is not part of the format. A `generation` key is refused, because a generation belongs to a cohort on one tenancy. Every problem is reported, not only the first.
- A field the survey reads that a subject lacks is an error. It names the field and the subject's position (for example `head_name` missing for subject 2), never the subject's ID.
- A field in the roster that no survey reads is a note, because the bundle builder drops it before the roster is sealed.
- A `consent-covers` name that none of the given surveys carries is an error. The output also says what the roster's consent covers, or that the factory will record the assigned surveys when it is issued.

`--instrument` takes a survey folder, and may be given more than once. A roster field is a note only when none of the surveys reads it. The command writes nothing and exits `1` when there is an error.

## Which surveys a consent covers

Consent is given for a survey. A roster's `granted` counts only for the surveys the roster version covers; for any other survey the collector records the person's consent on the device first, exactly as for `unknown`. `refused` refuses every survey.

```yaml
cohort: village-a
version: 3
consent-covers: [household-water-access]
subjects:
  - { subject: hh-0002, display: Household 2, consent: granted, fields: { head_name: Tomas } }
```

`consent-covers` is optional. When the file names it, `roster check --instrument` reports a name that none of the given surveys carries, which is nearly always a typo. When the file leaves it out, the factory records the surveys assigned to the cohort at the moment it accepts the roster (in any account), and that list is fixed with the version: a survey assigned later is not covered by it, and its `granted` people are asked for consent on the device until you issue a newer version that names the survey. `roster diff` reports a change of coverage between two versions.

## Which fields reach a device

Only the fields a survey reads (DIS-013). A roster file may carry more, such as a village code kept for your own records, and `roster check` tells you which ones will be dropped.

## Compare two versions

```sh
fieldseal roster diff examples/rosters/village-a.yaml examples/rosters/next/village-a.yaml
fieldseal roster diff village-a@3 examples/rosters/next/village-a.yaml --store ./rosters
```

Each side is a file, or `<cohort>@<version>` read from `--store`, a read-only copy of the factory's roster store. The output is counts: subjects added, removed and kept, consent changes by from and to state, whether the consent coverage changed, `prior_status` changes, and the names of the fields whose values changed. It shows no subject ID and no value.

`--reveal` adds the IDs and values and prints a warning on stderr. Use it only where the output is as private as the roster.

## List the stored versions

```sh
fieldseal roster list --store ./rosters
fieldseal roster list --store ./rosters --cohort village-a
```

Each line names a version as `<cohort>@<version>` with its digest, subject count and consent counts. It shows no subject ID.

## Issue a roster

```sh
fieldseal roster issue examples/rosters/village-a.yaml examples/rosters/cohort-a.yaml \
  --factory-url http://localhost:8080 --instrument examples/surveys/household-water-access
```

`roster issue` stores each file at the factory as its cohort's roster at the version the file names. It runs `roster check` on every file first and sends nothing if any fails; `--instrument` (optional, repeatable) adds the comparison with a survey. Then it signs you in once as the operator and sends the files. For each it prints the stored version and digest, or `unchanged` when the factory already holds exactly that roster at that version. A version never changes once stored: the same version with different content is refused, and so is a version lower than the latest. To change a roster, raise `version`.

## Assign a cohort to an account

```sh
fieldseal roster assign --factory-url http://localhost:8080 \
  --account 00000000-0000-4000-8000-000000000003 \
  --assign household-water-access=village-a --assign school-meals-baseline=cohort-a
```

An assignment says that one account collects one survey for one cohort. The account is the collector's OIDC subject, the `sub` claim of the collector's sign-in at the identity provider (in the local stack, `product-owner` is `00000000-0000-4000-8000-000000000003`). It applies to the tenancies that account has now and to those it registers later. The factory refuses a survey that is not published (`unknown-survey`) and a cohort with no stored roster (`unknown-cohort`), so publish and issue first. Giving the same assignment twice prints `unchanged`.

To see what has been assigned:

```sh
fieldseal roster assign --factory-url http://localhost:8080 --list
```

This prints the factory's journal of assignments, one line each: the account (the subject you sent), the survey, the cohort, the cohort's generation for that account, and who made it and when. It takes no `--account` or `--assign`.

Removal is not built. `roster assign` has no way to take an assignment away or to move a cohort to another tenancy; asking with `--remove` names REG-045 (moving a cohort records a succession with the generation raised by one) and stops.

## Signing in as the operator

`roster issue` and `roster assign` need an access token for the factory, from the identity provider's authorisation-code flow with PKCE. The CLI reads the provider from `FIELDSEAL_OIDC_ISSUER` and the client id from `FIELDSEAL_OIDC_CLIENT_ID` (`--issuer` and `--client-id` override them), starts a listener on the loopback interface and opens the authorisation URL with the command in `FIELDSEAL_BROWSER` or `--browser`. `--browser none` opens nothing and is for the development identity provider of `just web`, which signs in without a person; `--login <name>` picks the development login. The [local stack guide](./run-the-local-stack.md) shows both set-ups. Neither command prints a token.

## No subject IDs on screen

None of these commands prints a subject ID or a roster value unless you pass `--reveal` to `roster diff`. Findings name a subject by its position in the file.
