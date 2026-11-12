# v7 benign npm corpus

A benign npm dataset built on the VPS with the `npm` CLI: `npm search` picks the
long-tail candidates, `npm pack` fetches the published tarballs, and the v6
filtering rules turn them into a benign reference set.

## What it replaces

`experiments/v6/` built its corpus with `urllib` against the registry API, which
is rate limited for the per-package download counts. This version asks npm
itself, so a plain `npm` install is the only prerequisite and the download
counts come from the registry's bulk endpoint.

## Pipeline

```bash
python3 experiments/v7/scripts/fetch_benign_npm.py \
    --popular 1500 --longtail 1500 --search-per-keyword 120
python3 experiments/v6/scripts/build_benign.py \
    --raw ~/packguard-data/v7/raw/npm \
    --refs ~/packguard-data/v7/benign_refs \
    --val ~/packguard-data/v7/val/source \
    --val-popular 0 --val-longtail 0
```

`fetch_benign_npm.py` is incremental: tarballs already in `index.json` are kept,
and monthly download counts are cached in `downloads.json`.

`build_benign.py` is reused unchanged from v6. The validation split is off
(`--val-popular 0 --val-longtail 0`), so every package lands in the reference
set instead of being set aside for tuning.

## Selections

| | |
|---|---|
| Popular | Random latest versions from `npm-high-impact` 1.13.0, shuffled with seed 20261105, at most 1,500 |
| Long-tail | Last 120 hits of each of 167 generic keywords in `npm search`, at most 2,000 downloads a month, not deprecated, at most 1,500 |
| Excluded | 12,819 DataDog `malicious_intent` package names, taken from the repository's Git tree listing |
| Size cap | Tarballs over 8 MiB unpacked are skipped |

## Results (2026-11-05)

| | |
|---|---|
| Raw corpus | 2,821 tarballs (1,348 popular, 1,473 long-tail), 245 MiB |
| Search candidates | 16,999 long-tail names, 1,668 under the download cap |
| Reference set | 2,549 packages (1,215 popular, 1,334 long-tail), 29,654 files, 70.4 MiB of JavaScript |
| Dropped | 201 packages without JavaScript, 4,795 repeated files, 71 packages left empty by the deduplication |

Locations on the VPS: `~/packguard-data/v7/raw/npm/` and
`~/packguard-data/v7/benign_refs/` with `benign_refs_manifest.json` next to it.
Nothing is committed: the extracted files are not in the repository, only the
two scripts above.

## Usage

```bash
packguard --mode known -B ~/packguard-data/v7/benign_refs <malware_refs> <package>
```

## Combined malware references

`merge_malware_refs.py` folds the extracted v1 and v2 malware sets into one
directory, keeping a single copy of every file:

```bash
python3 experiments/v7/scripts/merge_malware_refs.py
```

On 2026-11-06 the 77,742 files of v1 and v2 held 23,444 distinct contents, so
54,298 duplicates were dropped and 1.66 GiB became 486 MiB. The combined set
reaches 91,639 distinct raw chunks against 72,518 for v1 and 73,420 for v2, and
leaves the score of a benign control unchanged.
