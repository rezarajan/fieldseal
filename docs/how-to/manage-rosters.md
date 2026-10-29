# Manage rosters

A roster lists the subjects of one cohort: an ID, the name the collector sees, a consent state and the values a survey reads as `roster.<field>`. This guide covers the three commands that work on files and a copy of the roster store: `roster check`, `roster diff` and `roster list`. Issuing a roster and assigning a cohort to a survey are operations of the factory and are not covered here.

## Check a roster against its survey

```sh
fieldseal roster check examples/rosters/village-a.yaml \
  --instrument examples/surveys/household-water-access
```

The command checks the file first, then compares it with the survey.

- The file must be a closed form: one cohort, a `version` of at least 1, unique subject IDs, a consent state of `granted`, `refused` or `unknown`, and no key that is not part of the format. A `generation` key is refused, because a generation belongs to a cohort on one tenancy. Every problem is reported, not only the first.
- A field the survey reads that a subject lacks is an error. It names the field and the subject's position (for example `head_name` missing for subject 2), never the subject's ID.
- A field in the roster that no survey reads is a note, because the bundle builder drops it before the roster is sealed.

`--instrument` takes a survey folder, and may be given more than once. A roster field is a note only when none of the surveys reads it. The command writes nothing and exits `1` when there is an error.

## Which fields reach a device

Only the fields a survey reads (DIS-013). A roster file may carry more, such as a village code kept for your own records, and `roster check` tells you which ones will be dropped.

## Compare two versions

```sh
fieldseal roster diff examples/rosters/village-a.yaml examples/rosters/next/village-a.yaml
fieldseal roster diff village-a@3 examples/rosters/next/village-a.yaml --store ./rosters
```

Each side is a file, or `<cohort>@<version>` read from `--store`, a read-only copy of the factory's roster store. The output is counts: subjects added, removed and kept, consent changes by from and to state, `prior_status` changes, and the names of the fields whose values changed. It shows no subject ID and no value.

`--reveal` adds the IDs and values and prints a warning on stderr. Use it only where the output is as private as the roster.

## List the stored versions

```sh
fieldseal roster list --store ./rosters
fieldseal roster list --store ./rosters --cohort village-a
```

Each line names a version as `<cohort>@<version>` with its digest, subject count and consent counts. It shows no subject ID.

## No subject IDs on screen

None of these commands prints a subject ID or a roster value unless you pass `--reveal` to `roster diff`. Findings name a subject by its position in the file.
