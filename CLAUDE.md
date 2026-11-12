# CLAUDE.md

Rules for working in the PackGuard repository.

## Comments in code

The only comments allowed are purpose comments placed directly above:

- a **function** declaration or definition: may span multiple lines;
- a **struct**: exactly one line.

No other comments of any kind:

- no trailing comments on fields, macros, array entries or statements;
- no comments inside function bodies;
- no file header comments;
- no `#endif` labels;
- no comments in config files such as `.dockerignore` or `Makefile`.

For public functions, put the comment on the declaration in the header. If information from a removed comment is still needed, move it into the function's comment.

```c
/*
 * Splits a file into overlapping chunks.
 * Returns 0 on success, -1 on failure.
 */
int foo(const char *path, chunk_list *out);

/* One window of a file. */
typedef struct {
    size_t offset;
    size_t length;
} file_chunk;
```

## Test files

- Test inputs for a function go in `tests/<functionname>_test/`, using the exact C function name plus `_test`. For example, `split_file()` uses `tests/split_file_test/`.
- Keep the original files and the generated ones in that folder. Don't delete them after a test run, and don't add them to `.gitignore`.

## Dataset

- `dataset_index.md` records where every dataset lives, how it was filtered and what is still missing; update it whenever a dataset changes.
- The v1 malware set is committed as 16 encrypted zips, `data/v1/malware_js_0.zip` to `malware_js_f.zip` (password `infected`), split by the first hex character of each code-shape folder. Inside are 5,904 DataDog npm `malicious_intent` packages as plain `.js` files with no `package.json`. These are live malware.
- Never commit extracted samples, only encrypted zips under GitHub's 100 MB file limit. Extract them only inside WSL: on Windows, antivirus quarantines the files and many paths exceed 260 characters.
- `data/` is stored byte for byte (`-text` in `.gitattributes`) so line-ending conversion never changes NCD results.
- v1 uses static ratios: at most 3 packages per code shape and at most 3 versions per package name, earliest published first. Only sample zips of 1 MiB or less were used.
- v1 goes for speed with the fewest features and static ratios; selectors and tuned ratios come in later versions, judged on accuracy vs time.
- The v2 malware set is committed as 16 encrypted zips, `data/v2/malware_js_0.zip` to `malware_js_f.zip` (password `infected`), built by `experiments/v2/scripts/build_dataset.py`. It holds 6,500 DataDog npm `malicious_intent` packages with their install scripts stored as `install_scripts.txt`, never as `package.json`. Its ratio was tuned on a time split: at most 1 package per code shape and 3 versions per package name, newest published first.
- Download DataDog samples as individual files from `raw.githubusercontent.com` with parallel connections; a git clone of that repository runs at about 180 KiB/s.
- Still to collect: `compromised_lib` samples (need a diff against the clean version), zips over 1 MiB, Backstabber's Knife Collection and MalwareBench (access on request), and a larger benign set. Install-script-only packages are in v2.

## Commits and pull requests

- Never credit Claude:
  - no `Co-Authored-By: Claude ...` trailer in commit messages;
  - no "Generated with Claude Code" line in PR descriptions;
  - no other mention of Claude as author, opener or contributor.
- Commits use the repository owner's git identity only.

# Server Access

PackGuard runs on a private GCE instance in `europe-central2-c`. It has no external
IP: SSH goes through IAP, which carries TCP only, and outbound internet comes from
the Cloud NAT `packguard-nat-ec2`. The login user is `fr9rx` (passwordless sudo),
not `root`.

## Connect

```bash
gcloud compute ssh instance-20261106-103127 --zone=europe-central2-c --tunnel-through-iap
```

On Windows `gcloud compute ssh` always launches PuTTY, so `C:\apps\pg.cmd` wraps the
same session in Windows OpenSSH inside Windows Terminal and starts an IAP tunnel on
`localhost:2222` when one is not already up:

```powershell
pg
pg ls -la
```

## Start and stop

```bash
gcloud compute instances start instance-20261106-103127 --zone=europe-central2-c
gcloud compute instances stop instance-20261106-103127 --zone=europe-central2-c
```

## Copy files

`gcloud compute scp` does not expand `~`, so pass absolute paths:

```powershell
gcloud compute scp --tunnel-through-iap --zone=europe-central2-c sample.tgz "instance-20261106-103127:/home/fr9rx/pg-scan/packages/"
```

## Where things are

| Path | Contents |
|---|---|
| `~/packguard` | Sparse clone: `stage 2 LLM Model`, `experiments`, `data/v1`, `data/v2` |
| `~/packguard/stage 2 LLM Model/v3/model_int8` | Stage 2 INT8 model, 258 MB, self-test 4/4 |
| `~/packguard-data/v1/malware_js` | v1 malware, 5,904 packages, 39,119 files |
| `~/packguard-data/v2/malware_js` | v2 malware, 6,500 packages, 38,623 files |
| `~/packguard-data/combined/malware_js` | v1 and v2 merged, one copy per file, 23,444 files |
| `~/packguard-data/v7/benign_refs` | Benign references, 2,549 packages |
| `~/pg-scan/packages` | Drop folder for the packages to detect |
| `~/pg-scan/reports` | Stage 1 JSON reports |

`packguard` and `packguard-cli` come from release `v6.0.1` and are installed in
`/usr/local/bin`. The v7 benign references were copied from the old VPS
`153.75.226.130`, whose password is in `serverpasskey.md`.

## Python

System Python is 3.13 and its pip is externally managed, so Stage 2 runs from a venv:

```bash
~/pg-venv/bin/pip install numpy onnxruntime tokenizers
export PATH=~/pg-venv/bin:$PATH
~/pg-venv/bin/python "stage 2 LLM Model/v3/stage2_filter.py" --self-test
```

## Scan

```bash
packguard --mode known -B ~/packguard-data/v7/benign_refs \
          -d ~/pg-scan/reports \
          ~/packguard-data/combined/malware_js ~/pg-scan/packages/*
```

## Limits

This account cannot add an external IP (`compute.subnetworks.useExternalIp`),
reserve one (`compute.addresses.create`) or create firewall rules
(`compute.firewalls.create`). The existing `default-allow-ssh` rule already opens
`tcp:22`; mosh in Termius needs an external IP plus a rule for `udp:60000-61000`,
and IAP cannot carry UDP, so mosh does not work on this instance as it stands.
