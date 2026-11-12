# Dataset index

Where the PackGuard datasets live.

## v1 malware set

| | |
|---|---|
| Location | `data/v1/malware_js_0.zip` to `malware_js_f.zip` in this repository: 16 zips, 123.8 MiB |
| Extract | Inside WSL only: `unzip -P infected data/v1/malware_js_0.zip -d <dir>`. On Windows, antivirus quarantines the files and many paths exceed 260 characters. |
| Layout | `<code-shape-id>/<package>@<version>/<file>.js`, in the zip named after the first character of `<code-shape-id>` |
| Size | 5,904 packages, 39,119 JavaScript files, about 708 MiB extracted |
| Built | 2026-10-23 |

### Source

- DataDog malicious-software-packages-dataset, `samples/npm/malicious_intent/`.
- Only sample zips of 1 MiB or less: 23,825 of 25,460. The 1,635 larger zips (about 21.6 GB) were skipped.

### Filtering (static ratios)

1. Packages whose JavaScript is identical to an already kept one, ignoring whitespace, are dropped (5,342).
2. At most 3 packages per code shape: the code with strings, numbers, comments and `_0x…` obfuscator names blanked out (5,089 dropped).
3. At most 3 versions per package name (3,632 dropped).
4. The earliest published samples are kept first.

Also dropped: 2,970 packages whose malware lives only in a `package.json` install script, 883 with no JavaScript, and 5 unreadable zips (`marked-cs`, `marked-ps`).

### Safety

- Only `.js`, `.cjs` and `.mjs` files are kept, outside `node_modules`.
- No `package.json` is kept, so npm lifecycle scripts cannot run.
- The zips are encrypted (ZipCrypto, password `infected`, the same convention as DataDog), so antivirus and accidental runs can't reach the files.
- No file has an execute bit, and git stores the zips byte for byte (`-text`).
- The files are real malware. Read them as text only and never run them with `node`, `npm` or Windows Script Host.

### Size profile

- Median package: about 2.9 KB of JavaScript.
- 4,538 packages (77%) have 16 KiB or less, 13.7 MiB in total. A few large packages hold most of the bytes.

### Kept packages by publish year

| Year | Packages |
|---|---|
| 2018–2022 | 11 |
| 2024 | 515 |
| 2025 | 3,371 |
| 2026 | 2,007 |

### Integrity

On 2026-10-24 an extracted copy in WSL (`~/packguard-data/v1/malware_js/`) was compared with the 16 zips by CRC-32 and size: all 39,119 files match, none missing or extra. The v1 detailed test below used that copy.

### Distinct chunks

Split into the v1 chunks (files over 16 KiB as 8 KiB windows every 4 KiB), the set has 190,939 chunks but only 69,249 distinct ones. The scanner scores each distinct chunk once.

## v1 detailed test set

Built 2026-10-24 to measure v1 stage 1 on malware and benign packages it has not memorised. Results and analysis: [`experiments/v1/`](experiments/v1/README.md).

| | |
|---|---|
| Location | WSL only, `~/pg-detailed/targets/<category>/<package>@<version>/`, not committed (live malware). Rebuild with the scripts in `experiments/v1/scripts/`. |
| Size cap | At most 32 KiB of JavaScript per package, so the benign packages match the malware's sizes (v1 median 2.9 KB) and the run fits in a few hours |
| Malware files | Only `.js`, `.cjs` and `.mjs`, no `package.json`, decrypted in memory, written read-only, named as in v1 |
| Seeds | Python `random.Random(20261024)` for malware, `20261025` for benign, `7` for the scan order |

| Category | Packages | How it was chosen | Dropped while collecting |
|---|---|---|---|
| `mal_known` | 50 | Random v1 packages of 32 KiB or less. Scored as is (trivial: they are in v1) and with their family left out (see the analysis). | none |
| `mal_newver` | 35 | For random v1 names at the 3-version cap, one DataDog version the cap dropped (zip of 200 KB or less) | 4 without JavaScript, 9 over 32 KiB |
| `mal_newname` | 35 | Random DataDog `malicious_intent` zips (200 KB or less) whose package name is not in v1: packages v1 dropped as code-shape or exact duplicates | 5 without JavaScript, 1 over 32 KiB |
| `ben_popular` | 50 | Latest version of well-known npm packages (the list is in `fetch_benign.py`), none in the DataDog manifest | 3 over 32 KiB |
| `ben_longtail` | 25 | npm search results for 42 generic keywords, at most 2,000 downloads a month, last published 2015-01-01 to 2024-06-30, not deprecated, none in the DataDog manifest | 5 without JavaScript, 15 over 32 KiB |

For every `mal_newver` and `mal_newname` file the manifest records whether it is identical to a v1 file once whitespace is ignored (the v1 duplicate rule), so the analysis can score only the files v1 has never seen.

The benign sets are labelled benign because they are on the registry, not deprecated and not in any DataDog list; they were not audited by hand. The long-tail set is small (25) because few search results met the filters within the size cap.

## v4 mangling benchmark

| | |
|---|---|
| Location | WSL only, `~/pg-v4/targets/`, `~/pg-v4/scan/` and `~/pg-v4/reports/`; not committed (live malware) |
| Source | v1 detailed test set: 120 malware (50 `mal_known`, 35 `mal_newver`, 35 `mal_newname`) and 58 benign packages with JavaScript (41 `ben_popular`, 17 `ben_longtail`) |
| Transforms | T1 format, T2 rename identifiers/strings/numbers/files, T3 18 KiB dead-code padding, T4 whole-file base64 |
| Size | 712 targets: 480 malware variants and 232 benign controls across the four tiers |
| Built | 2026-10-27 by `experiments/v4/scripts/mangle.py` (committed) |
| Results | [`experiments/v4/`](experiments/v4/README.md) |

The original sample stays in the v1 reference set and only the transformed copy is scored, so this measures known-family robustness, not an unseen family or a new campaign. Some source packages have no JavaScript, which is why the benign set is 58 packages rather than 75. No encrypted dataset zip changed.

## v2 malware set

| | |
|---|---|
| Location | `data/v2/malware_js_0.zip` to `malware_js_f.zip` in this repository: 16 zips, 123 MiB (5.4–10.6 MiB each) |
| Extract | Inside WSL only: `unzip -P infected data/v2/malware_js_0.zip -d <dir>` |
| Layout | `<code-shape-id>/<package>@<version>/<file>`, in the zip named after the first character of `<code-shape-id>`. Files are `.js`, `.cjs`, `.mjs` and `install_scripts.txt` |
| Size | 6,500 packages in 6,500 code shapes, 38,623 files, 654 MiB of content (807 MiB on disk extracted) |
| Built | 2026-10-26 by `experiments/v2/scripts/build_dataset.py` (committed, unlike the v1 builder) |

### Source

- DataDog malicious-software-packages-dataset, `samples/npm/malicious_intent/`, downloaded 2026-10-25 by `fetch_datadog.py`: all 23,825 zips of 1 MiB or less (1.1 GiB). DataDog had added nothing since v1 was built.
- 22,907 are usable: every zip opened (v1 lost 5), and 918 hold neither JavaScript nor install scripts.

### What is new compared with v1

- **Install scripts.** Each package's root `package.json` is reduced to its `preinstall`, `install` and `postinstall` commands, one per line, stored as `install_scripts.txt`, never as `package.json`. That is the same text the scanner extracts from a target's `package.json`. Commands that only launch a local `.js` file (`node index.js`, with optional redirects, `|| true` or `exit 0`) are left out, since the file itself is kept and the command alone matches benign packages. 1,991 packages keep install scripts, and 952 of them have no JavaScript at all: v1 had to drop such packages.
- **Tuned ratio instead of v1's static one.** At most **1 package per code shape** and **3 versions per package name**, **newest published first**. This was chosen by the ratio experiment in [`experiments/v2/`](experiments/v2/README.md): more examples per shape added no detection, and newest-first raised AUC at the lowest cost.
- **Code shape** (`js_shape()` and `script_shape()`): per JavaScript file, strings, numbers, comments and `_0x…` names are blanked and whitespace is removed. Per install-script text, words longer than 10 letters or holding digits become `#`. The package shape is the hash of its sorted file shapes. This rule is finer than v1's (9,583 shapes over the usable packages), so v2's shape ids differ from v1's folder names.

### Filtering

1. Packages whose stored files are identical to an already kept one, ignoring whitespace, are dropped (8,689 of 22,907).
2. In order of publication date, newest first, a package is kept while its code shape has no kept package and its name has fewer than 3. 6,500 are kept.

### Kept packages by publish year

| Year | Packages |
|---|---|
| 2024 | 469 |
| 2025 | 3,900 |
| 2026 | 2,131 |

### Integrity

On 2026-10-26 all 16 zips passed `unzip -t` (CRC) with the password, and they hold 38,623 files, the same as the extracted copy in WSL (`~/packguard-data/v2/malware_js/`). No file is named `package.json` and none has an execute bit.

## v2 ratio test set

Built 2026-10-25 to choose the v2 ratio and to measure install scripts. Results: [`experiments/v2/`](experiments/v2/README.md).

| | |
|---|---|
| Location | WSL only, `~/pg-v2/targets/<category>/<package>@<version>/`, not committed. Rebuild with `experiments/v2/scripts/`. |
| Time split | References from malware published before 2026-04-01 (19,872 usable packages); malware tests published on or after it (3,035) |
| `mal_shape` | 300 packages: one random package from each of 300 random code shapes, at most 64 KiB stored (seed 20261025). Only 9 share a code shape with older malware. |
| `mal_stream` | 200 random packages after the cutoff, clones included (seed 20261025) |
| `ben_general` | 400 packages from the `npm-high-impact` 1.13.0 list (none in DataDog `malicious_intent`, latest version not deprecated and not a DataDog `compromised_lib` version), at most 64 KiB of JavaScript, with their `package.json`. 203 were too big and 58 had no JavaScript. |
| `ben_scripts` | 64 of 5,612 probed popular packages whose latest version has install scripts (`package.json` only) |

## v6 raw benign npm corpus

Downloaded 2026-10-29 by `experiments/v6/scripts/fetch_benign_corpus.py`. This is the raw input; everything below is filtered from it.

| | |
|---|---|
| Location | WSL only: `~/packguard-data/raw/npm/tarballs/<name>@<version>.tgz`, the registry tarballs unchanged (857 MiB). `~/packguard-data/raw/npm/index.json` records name, version, tarball URL, unpacked size and source per tarball; `~/packguard-data/raw/npm/search/` caches the npm search pages. Not committed. |
| Size | 6,014 tarballs: 3,556 `popular`, 2,458 `longtail` |
| `popular` | Random latest versions from the `npm-high-impact` 1.13.0 list (seed 20261029), not deprecated |
| `longtail` | npm search results (two pages of 250) for generic keywords, at most 2,000 downloads a month, not deprecated or flagged insecure. The script lists 167 keywords (the 42 v1 long-tail keywords plus 125 more); 85 returned results, the rest were refused by the registry's search rate limit |
| Excluded | Every package name in DataDog `malicious_intent`, the v1 detailed-test benign set and the v2 benign set (13,380 names), so no test package can enter the references. Tarballs with an unpacked size over 8 MiB were skipped. |

Raw tarballs are kept so the filter can be changed and rerun without downloading again (`build_benign.py` takes about 25 s).

## v6 benign reference set

| | |
|---|---|
| Location | WSL only: `~/packguard-data/v6/benign_refs/<name>@<version>/<path with / as __>`; manifest in `~/packguard-data/v6/benign_refs_manifest.json` (a copy is in `experiments/v6/results/`). Not committed. |
| Built | 2026-10-29 by `experiments/v6/scripts/build_benign.py` from the raw corpus, after the validation packages below were set aside |
| Size | 5,211 packages (3,130 popular, 2,081 long-tail), 67,703 files, 171 MB of JavaScript; the scanner keeps 76,909 distinct raw chunks and 50,211 distinct normalised chunks |
| Filter | `.js`, `.cjs`, `.mjs` outside `node_modules`; files of 64 KiB or less, smallest first, at most 128 KiB per package; files identical to one already kept (whitespace ignored) are dropped (7,444); 546 packages had no JavaScript |
| Use | `packguard -B <dir>`: a chunk only counts when it is closer to malware than to this set by the margin |

## v6 validation set

Built 2026-10-29 to tune the v6 rule without touching the v4 benchmark (the test set). Same design as the v4 benchmark, different packages.

| | |
|---|---|
| Location | WSL only: sources in `~/pg-v6/val/source/<category>/`, transformed targets in `~/pg-v6/val/targets/<tier>/<category>/`, scan links in `~/pg-v6/val/scan/`. Not committed (live malware). |
| `mal_known` | 50 random v1 packages of 32 KiB or less whose name is not in the v4 test set (seed 20261029) |
| `mal_newver` | 35 DataDog versions dropped by the v1 version cap, for names at the cap and not in the v4 test set; zip of 200 KB or less, 32 KiB of JavaScript or less |
| `mal_newname` | 35 DataDog packages whose name is in neither v1 nor the v4 test set; same size limits |
| `ben_popular` | 60 popular packages from the raw corpus, at most 32 KiB of JavaScript, not in the benign references |
| `ben_longtail` | 60 long-tail packages from the raw corpus, last published by 2024-06-30, at most 32 KiB of JavaScript, not in the benign references |
| Transforms | `experiments/v4/scripts/mangle.py --seed 20261030`: T1–T4 as in v4, 960 targets (480 malware variants, 480 benign controls) |
| Scripts | `select_val_malware.py` (decrypts DataDog zips in memory, writes read-only files), `build_benign.py` |

## v7 benign npm corpus

Downloaded on 2026-11-05 on the VPS by `experiments/v7/scripts/fetch_benign_npm.py`, driven by the `npm` CLI (`npm search` and `npm pack`). This is the raw input for the reference set below; see [`experiments/v7/`](experiments/v7/README.md).

| | |
|---|---|
| Location | VPS only: `~/packguard-data/v7/raw/npm/tarballs/<name>@<version>.tgz`, the registry tarballs unchanged (245 MiB). `~/packguard-data/v7/raw/npm/index.json` records name, version, tarball URL, sizes and source per tarball; `search/` caches the `npm search` results; `downloads.json` caches the monthly download counts. Not committed. |
| Size | 2,821 tarballs: 1,348 `popular`, 1,473 `longtail` |
| `popular` | Random latest versions from the `npm-high-impact` 1.13.0 list (seed 20261105), not deprecated |
| `longtail` | The last 120 hits of each of the 167 keywords in `npm search`, at most 2,000 downloads a month, not deprecated; 16,999 candidates, 1,668 under the cap |
| Excluded | The 12,819 package names in DataDog `malicious_intent`, taken from the repository's Git tree listing and cached as `~/packguard-data/datadog/tree_malicious_intent.json` |

## v7 benign reference set

| | |
|---|---|
| Location | VPS only: `~/packguard-data/v7/benign_refs/<name>@<version>/<path with / as __>`; manifest in `~/packguard-data/v7/benign_refs_manifest.json`. Not committed. |
| Built | 2026-11-05 by `experiments/v6/scripts/build_benign.py` with the validation split turned off, so no package is set aside |
| Size | 2,549 packages (1,215 popular, 1,334 long-tail), 29,654 files, 70.4 MiB of JavaScript |
| Filter | `.js`, `.cjs`, `.mjs` outside `node_modules`; files of 64 KiB or less, smallest first, at most 128 KiB per package; files identical to one already kept (whitespace ignored) are dropped (4,795); 201 packages had no JavaScript and 71 were left empty by the deduplication |
| Use | `packguard -B <dir>`: a chunk only counts when it is closer to malware than to this set by the margin |

## Combined malware reference set

| | |
|---|---|
| Location | VPS only: `~/packguard-data/combined/malware_js/<package>@<version>/<file>`; manifest in `~/packguard-data/combined/malware_js_manifest.json`. Not committed (live malware). |
| Built | 2026-11-06 by `experiments/v7/scripts/merge_malware_refs.py` from the extracted v1 and v2 sets, keeping a single copy of every file |
| Size | 8,440 package folders, 23,444 files, 486 MiB; 54,298 identical files dropped, 699 of which differed only in whitespace |
| Coverage | 91,639 distinct raw chunks and 19,213 normalised chunks, against 72,518 / 16,720 for v1 and 73,420 / 17,221 for v2 |
| Use | One `packguard` run against both malware sets. A package whose files all duplicate an earlier one keeps no folder of its own, because its chunks are already in the set. |

The benign control `accepts@1.3.8` scores 0.6193 against the combined set, the same as against v1 or v2 alone, so the deduplication changes no verdict. Load time is 19.4 s against 19.2 s for v1 alone.

## Mode test sets: known and new

Built 2026-11-06 on the GCE instance by `test-sets/scripts/run_server.sh`. These are the large mixed-provenance sets for the two stage-1 modes: each set contains downloaded packages (`real/`) and generated packages (`invented/`). Nothing is committed; generated sample folders are ignored by `test-sets/.gitignore`.

| | |
|---|---|
| Location | GCE only: `~/pg-test-sets/known/{real,invented}/<category>/<package>@<version>/` and `~/pg-test-sets/new/{real,invented}/<category>/<package>@<version>/`. Manifests in `~/pg-test-sets/manifest_invented.json` and `manifest_real.json`; summaries in `stats.json` and `report_stats.json`. |
| Size | 20,135 packages: known real 4,200, known invented 6,850, new real 1,885, new invented 7,200; about 391 MiB of plaintext plus a 215 MiB DataDog download cache |
| Known categories | `mal_known` 720, `mal_newver` 500, `mal_newname` 2,500, `mal_scripts` 480, `T1_format`/`T2_rename`/`T3_padding`/`T4_base64` 530 each, `payload_base64`/`payload_hex` 265 each, and 600 each of `install_scripts`, `typosquat`, `dropper`, `stealer`, `padded_loader`, `encoded_loader`, `multi_stage` |
| New categories | `mal_shape` 285, `mal_stream` 900, `mal_scripts` 300, `mal_encoded` 400, plus 300 each of `net_host`, `net_sensitive`, `webhook_exec`, `env_exec_net`, `eval_decode`, `obfuscated`, `stream_clone`, `reverse_shell`, `wallet_stealer`, `credential_harvest`, `dns_beacon`, `crypto_miner`, `telegram_bot`, `discord_webhook`, `env_dump`, `obfuscated_loader`, `split_payload`, `hex_loader`, `script_net_host`, `script_net_sensitive`, `script_net_encoding`, `script_reverse_shell`, `script_dependency_confusion`, `script_env_exfil` |
| Real sources | The extracted v1/v2 corpora (`~/packguard-data/v1|v2/malware_js`) for `mal_known` and `mal_scripts`; a 6,500-zip DataDog `malicious_intent` download pool for `mal_newver`, `mal_newname` and the new set. The pool excludes every name already in v1/v2; a downloaded name whose code shape matches a v2 shape becomes `mal_newname`, the rest feed `mal_shape`, `mal_stream`, `mal_scripts` and `mal_encoded`. |
| Invented sources | `T1`–`T4` and the payload folders are transforms of sampled v1/v2 packages; the remaining known folders and all 24 new folders are authored inert packages from `test-sets/scripts/generate_invented.py`. Every endpoint is under `.invalid`, every credential or wallet path is dummy, and no command is destructive or persistent. |
| Validation sample | Known: T1–T4 10/10 each, `mal_known` 10/10, `mal_newname` 9/10, `mal_newver` 125/200, `mal_scripts` 20/20. New: `mal_shape`/`mal_stream`/`mal_scripts`/`mal_encoded` 20/20 each and the sampled invented categories 20/20 each. Reports are in `~/pg-test-sets/reports/`. |
| Reproduce | `cd ~/packguard/test-sets/scripts && ./run_server.sh`, then `./scan_sets.sh known` or `./scan_sets.sh new`. `build_real.py --pack` writes encrypted per-category archives under `~/pg-test-sets/zips/` for safe copying. |

`mal_newver` is the known-mode weak spot in the sample: a new version often moved its attack into an install script with a new endpoint, so the old version in the references no longer matches. The new mode's primitive channel is the path for them; run `--mode new` over the same packages. The authored packages in the known set are novel code too, so known mode may miss them; they mark the boundary between the two modes.

### Local encrypted export

On 2026-11-07 the four folders were packed on the instance into ZipCrypto archives (password `infected`) and copied to the Windows checkout under `data/from-instance/`. Each set is split into 16 zips by the first hex character of the package name; extract all 16 into one directory to reconstruct the flat set. The archives are well under GitHub's 100 MiB limit (largest 6.53 MiB). The manifests are `manifest_combined.json`, `manifest_benign.json`, `manifest_known.json` and `manifest_new.json` in the matching folders.

| Folder | Zips | Size | Packages |
|---|---:|---:|---:|
| `data/from-instance/combined/` | 16 | 76.1 MiB | 8,440 |
| `data/from-instance/benign/` | 16 | 27.1 MiB | 2,549 |
| `data/from-instance/known/` | 16 | 33.1 MiB | 11,050 |
| `data/from-instance/new/` | 16 | 12.2 MiB | 9,085 |

Built by `test-sets/scripts/export_encrypted.py`. The combined, known and new archives contain live malware; extract them only on the instance or in WSL. The benign archive is ordinary npm code.

On 2026-11-07 the instance copies under `~/pg-test-sets` and `~/packguard-data` were deleted after this export was verified, so the encrypted archives in `data/from-instance/` are now the only copy. The generators and the scan harness remain in `test-sets/scripts/`; rebuilding needs the v1/v2 zips in `data/` and a fresh benign reference download.

## Not yet collected

- DataDog `compromised_lib` samples: real libraries with injected code, need a diff against the clean version.
- The 1,635 DataDog zips over 1 MiB.
- Backstabber's Knife Collection and MalwareBench: access on request.
- MalOSS: the repository has package-name lists only; samples come from the authors.
- OpenSSF malicious-packages: reports only, used to confirm live-scan detections.
- A larger benign test set, including packages over 32 KiB. The v6 raw corpus (6,014 packages) and the v7 corpus (2,821 packages) feed the benign references, but the v4 benchmark still has only 58 benign packages per tier, so its false-alarm rate is a rough estimate.
