# Export results to Parquet

This guide shows how to turn a landing directory into the results export, and the export into a Parquet file. For the rules of the export, see requirements INT-085 to INT-088 in the [intake specification](../reference/spec/intake.md).

The files you write are outside Fieldseal's protection. They hold free text, special-category items (the data contract marks them), the consent basis and record, and tenancy and sequence ids. Keep them where only people who may see that data can read them.

## Before you start

You need four things:

- The intake app's landing directory, the one that holds `observations.csv`.
- The directory of `*.published` files that the intake app reads, and the trust bundle that verifies them. The landing rows name each instrument by a salted fingerprint, and only the publications can turn the fingerprint into a data contract.
- The export key file, `export.key`: 32 random bytes with file mode 0600. The authority's set-up step creates it (`tools/stack-init.sh` in the stack, `tools/dev-web.sh` in `just web`). The command never creates a key, and it refuses a file that is missing, not 32 bytes long or readable by others.
- A directory to write into.

## Write the export

```sh
fieldseal intake results \
  --landing landing/ --published published/ \
  --export-key export.key --trust-bundle trust-bundle.bundle \
  --out results/
```

The command reads `observations.csv` once, so every file comes from one snapshot of the landing. It prints each file, the SHA-256 of `manifest.json` and a reminder that the files are unprotected. Add `--format jsonl` or `--format csv` to write only one of the two formats.

| File | What it holds |
|---|---|
| `results.jsonl`, `results.csv` | One row per landed answer, nonresponse or retraction. JSON Lines has typed columns (`value_number`, `value_text`, `value_date`, `value_bool`, `value_codes`); CSV keeps one `value` column and `value_type`. |
| `free_text.jsonl`, `free_text.csv` | The text of free-text items: `record_id`, `item_path`, `value_text`. |
| `contracts/<fingerprint>.json` | The data contract of each instrument, named by its fingerprint in 64 lower-case hex digits. |
| `codebook.csv` | Item and code labels in every language, rendered from the contracts. |
| `manifest.json` | The export version, the landing mark, the key id, the instruments, the layouts, the digest of every other file and the number of rows left out. |

Some rules help when you read the files:

- Rows that consent or a custodian excluded are not in any file. The manifest counts them in `rows_omitted_excluded`.
- `subject` is a keyed hash of the pseudonymous subject, so the same key gives the same value in every export from one authority, and another authority's key gives different values.
- `value_number` is exact text, never a floating-point number. Cast it with the precision you want.
- `tick_lower_bound` and `received_at` are integers in milliseconds since the Unix epoch on the authority clock, with no time zone (UTC).
- A free-text answer keeps its row in the results table with every value column empty. Its text is in the free-text files.
- A CSV text cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return has a `'` in front, so a spreadsheet does not run it as a formula. Numbers never have one. A program that reads the CSV should strip one leading `'` from a text cell that starts with `'=`, `'+`, `'-`, `'@`, a `'` and a tab, or a `'` and a carriage return. JSON Lines is never changed.

## Convert to Parquet

With [DuckDB](https://duckdb.org):

```sh
duckdb -c "COPY (SELECT * REPLACE (CAST(value_number AS DECIMAL(38,9)) AS value_number)
                 FROM read_json_auto('results/results.jsonl'))
           TO 'results.parquet' (FORMAT PARQUET)"
```

To see the free text next to the answers, join on the record and the item:

```sh
duckdb -c "SELECT r.*, f.value_text AS free_text
           FROM read_json_auto('results/results.jsonl') r
           LEFT JOIN read_json_auto('results/free_text.jsonl') f USING (record_id, item_path)"
```

To turn the time columns into timestamps, use `make_timestamp(received_at * 1000)` (DuckDB counts microseconds) or `epoch_ms(received_at)`.
