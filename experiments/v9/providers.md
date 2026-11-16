# v9 npm malware providers (other than DataDog)

Checked on 2026-11-15 by listing GitHub trees and Zenodo records through their APIs. No sample was downloaded to the Windows machine. Server smoke tests of `experiments/v9/scripts/fetch_providers.py` ran with `--limit 25` per provider and passed.

## Fetchable without any request

| Provider id | URL | Access | Licence or terms | npm samples | Format and layout | Publish dates |
|---|---|---|---|---|---|---|
| `npmanalysis` | https://github.com/lxyeternal/NPMAnalysis, folder `Dataset/zip_malware` | open | none stated (research-use repo, no LICENSE file) | 6,420 tgz, 4,286 package names, 2.04 GB. Compiled from Backstabber's Knife Collection, DONAPI, GuardDog and others (per its README) | plain `.tgz` per version, no password: `<name>/<version>/<file>.tgz`, scoped names written `@scope##name`. Samples are normal git blobs, not LFS | 6,149 of 6,420 from `Core/Data/timecollect/time/malware_time.csv` (npm registry timestamps) |
| `malpkg` | https://github.com/lxyeternal/malicious-package-dataset, folder `npm` | open | none stated; README says academic and research use only | 19,061 tgz of 100 bytes or more, 4,390 package names, 3.8 GB. Built from OSV and Snyk malware reports | same layout as above. 8,703 further `.tgz` of 46 to 99 bytes are empty gzip stubs and are skipped. Some folders hold only `metadata.json` or loose files and are skipped | none in the repo. The fetcher joins the NPMAnalysis time table: 4,411 of 19,061 dated |
| `npmzoo` | https://github.com/spaceraccoon/npm-zoo | open | Apache-2.0 | 7 unpacked packages (commander-js 2.19.84, device-mqtt 1.0.11, flatmap-stream 0.1.1, pizza-pasta 1.0.3, portionfatty12 2.0.0, rrgod 1.0.0, stream-combine 2.0.2), 0.7 MB. The set is an ad hoc zoo and may include benign look-alikes | unpacked directories in a shallow clone, `packages/<name>/<name>-<version>/`, format `dir` | none |

Overlap: `npmanalysis` and `malpkg` share 4,480 name+version pairs. Their union is 21,001 name+version pairs. Overlap with the DataDog set was not measured. The other agent's dedup (by name+version or content hash) should handle it.

Neither lxyeternal repo says how each sample was verified as malicious, so treat them as report-derived labels, not human-vetted ones. Both are about 6 GB of git history, so the fetcher reads individual files from `raw.githubusercontent.com` and never clones them.

## Full run

```
python3 experiments/v9/scripts/fetch_providers.py all --out ~/packguard-data/v9/raw
python3 experiments/v9/scripts/fetch_providers.py npmanalysis
python3 experiments/v9/scripts/fetch_providers.py malpkg --workers 16
python3 experiments/v9/scripts/fetch_providers.py npmzoo
```

Expected download: about 5.9 GB in about 25,500 files (2.04 GB `npmanalysis`, 3.8 GB `malpkg`, under 1 MB `npmzoo`). The run is resumable: finished files are skipped, partial ones use `.part` and are renamed on success. `index.json` is rewritten at the end of each provider. An interrupted run needs the same command again. The largest single file is 103 MB. The fetcher uses the GitHub API only twice per provider (60 requests per hour unauthenticated is enough).

## Blocked or not useful

| Source | URL | Access | Terms | npm count | Why it is not fetched, and how to get it |
|---|---|---|---|---|---|
| Backstabber's Knife Collection (Ohm et al. 2020) | https://dasfreak.github.io/Backstabbers-Knife-Collection/ (landing page; repo `dasfreak/Backstabbers-Knife-Collection`) | request | free for verified security research and academic evaluation; no licence text; cite the DIMVA 2020 paper | `data/packages.json` lists 15,882 npm names (plus 4,483 PyPI, 3,768 gem and others), names only | The landing page publishes names, not contents. To request: email `ohm[at]cs.uni-bonn.de` from an institutional address (no Gmail or Yahoo), state the research goal and framework method, and give an institutional GitHub username. Part of its npm content already sits in `npmanalysis`. The old repo `cybertier/Backstabbers-Knife-Collection` now returns 404 |
| MalwareBench (Zahan et al., MSR 2024) | https://github.com/MalwareBench, Zenodo https://zenodo.org/record/10573493 | request | access on reasonable request, with ethics considered | 20,792 npm+PyPI packages, 6,659 malicious (MSR paper: 20,534 and 6,475) | Fill the Google form linked on the org profile (https://forms.gle/A5h73BrxS1qsxfaU9) or email the authors. They then grant GitHub access. Zenodo has only a sample CSV. Data derives from Backstabber's and Socket, so it overlaps |
| MalOSS (Duan et al. NDSS 2021) | https://github.com/osssanitizer/maloss | open, but names only | repo licence file present; samples not included | about 30 npm name lists (`npmjs-mal-pkgs*.txt`, a few hundred names in total, with stats) | The repo holds name lists only, a few benign sample tgz and 40 to 60 MB dependency pickles. Samples come from the authors (CyFI-Lab-Public/maloss is a mirror) |
| OpenSSF malicious-packages | https://github.com/ossf/malicious-packages | open | Apache-2.0 (LICENSE present) | thousands of OSV reports | Reports only (OSV JSON, no package contents). Useful as labels and for confirming detections, not as samples |
| Amalfi artifact (Sejfia et al. ICSE 2022) | https://github.com/githubnext/amalfi-artifact, Zenodo https://zenodo.org/records/5908852 | open | CC-BY-4.0 | CSV rows of name, version, hash and label | The README says sample contents were withheld on purpose. Zenodo holds a single 7.4 MB zip of the same data |
| Zenodo "NPM ecosystem dataset" | https://zenodo.org/records/21414060 | open | CC-BY-4.0 | `malicious_packages_satadog.jsonl` (1.7 MB) and a deduplicated 0.9 MB file | Described as taken from the DataDog dataset, so it is a duplicate source. The files were listed, not read. Its other files are 80 MB of names and 668 MB of install scripts, not samples |
| MalwareBazaar (abuse.ch) | https://bazaar.abuse.ch/api/ | key | official docs say every API call needs an `Auth-Key` header | no npm tag found in a web search; the service holds mostly binaries and scripts | Needs a free abuse.ch account and key (https://auth.abuse.ch/user/me). Downloads are zips with password `infected` with a daily limit. Not used, since keys must not be created on anyone's behalf |
| IntelGuard, IntelliRadar, PyGuard (lxyeternal) | https://github.com/lxyeternal | open | none stated | no package archives | These hold intelligence articles, code snippets and tool code. Not samples |
| `lxyeternal/pypi_malregistry` | https://github.com/lxyeternal/pypi_malregistry | open | none stated | 0 (PyPI only, 1.5 GB) | PyPI, out of scope |
| DONAPI, Cerebro, MalWuKong | papers only | none found | n/a | n/a | No public sample repository or Zenodo record was found. Cerebro availability is stated inconsistently in surveys, and MalWuKong is listed as not released. The authors would have to be asked |
| `hogiathang/malware-dataset` | https://github.com/hogiathang/malware-dataset | gone | n/a | n/a | Referenced by `packguard-dev/MalPackSlice`, but both it and `benign-datasets` return 404 |

## Output contract

Each provider folder has `index.json`, a JSON list of objects with the keys `provider`, `category`, `name`, `version`, `published`, `archive`, `format`, `password` and `bytes`. Format is `tgz` for `npmanalysis` and `malpkg` (password null) and `dir` for `npmzoo`. Scoped names are written `@scope/name`. `category` is always null because these sources carry no label. `bytes` is the on-disk size of the archive, or of the whole directory for `dir`.
