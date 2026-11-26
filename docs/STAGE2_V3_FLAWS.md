# Stage 2 v3: flaws found in the standalone test (2026-11-12)

## What was run

Stage 2 v3 (`model_int8`, threshold 0.62) scored every package directly, with no Stage 1 gate, on a 3-vCPU Debian server. Packages were read with `package_dir_to_record()` from `stage2_filter.py`.

| Set | Packages | Flagged | Rate |
|---|---|---|---|
| `known` (malicious) | 11,050 | 8,822 | 79.8% recall |
| `new` (malicious) | 9,085 | 7,696 | 84.7% recall |
| `benign` (v7 benign references) | 2,549 | 390 | 15.3% false alarms |

A second run on a random sample (450 benign, 800 malicious) recorded the raw network probability next to the final probability, so the network and the rule layer can be judged separately. Sample figures below come from that run.

Limits of this test: it is Stage 2 alone, not the pipeline; the sample figures have a few points of noise; whether any of the benign packages were in the training data was not checked.

## Results per category

Lowest first. Categories at 100% are left out.

| Set | Category | Flagged | Rate |
|---|---|---|---|
| new | `credential_harvest` | 0/300 | 0.0% |
| new | `stream_clone` | 0/300 | 0.0% |
| known | `payload_base64` | 10/265 | 3.8% |
| new | `obfuscated_loader` | 48/300 | 16.0% |
| new | `eval_decode` | 80/300 | 26.7% |
| known | `payload_hex` | 112/265 | 42.3% |
| known | `encoded_loader` | 280/600 | 46.7% |
| known | `padded_loader` | 313/600 | 52.2% |
| new | `obfuscated` | 183/300 | 61.0% |
| known | `T2_rename` | 365/530 | 68.9% |
| known | `T4_base64` | 372/530 | 70.2% |
| known | `T3_padding` | 378/530 | 71.3% |
| known | `T1_format` | 412/530 | 77.7% |
| known | `mal_known` | 591/716 | 82.5% |
| known | `mal_newname` | 2,075/2,501 | 83.0% |
| known | `mal_newver` | 450/498 | 90.4% |
| new | `mal_stream` | 820/899 | 91.2% |

## Flaw 1: the rule layer overrides the network, and causes most false alarms

`compute_v3_calibrated_probability()` replaces the network's probability with fixed values whenever a regex matches.

- In the sample, 70 benign packages were flagged. The network alone flagged 17 of them; the rules pushed the other 53 (76%) over the threshold.
- The values the flagged benign packages land on are the rule constants: 0.86 (25), 0.82 (17), 0.88 (13), 0.78 (12).
- Every benign package with an `exec`/`spawn`/`child_process` match was flagged (27/27), every one with a "trojan" keyword match (13/13), and 18 of 19 with a network keyword match.
- The "trojan" regex contains ordinary words: `ipAddress`, `operatingSystem`, `useStyle`, `depay`. One match forces 0.88.
- The network regex contains `axios`, `fetch(`, `discord`, `telegram`, `webhook`. Any of these plus one `process.x` access forces 0.82.
- In rule 4, `total_exec >= 1 and (... or any_cp)` is always true when `total_exec >= 1`, because `any_cp` is set by the same match. So one `execSync` call forces 0.86 by itself.

Example: a three-line helper that runs `git rev-parse HEAD` gets 0.27 from the network and 0.86 after the rules.

## Flaw 2: the same rules hide real malware, and are easy to evade

Caps are applied before the positive rules and return immediately.

- In the sample, 125 malicious packages were missed. The network had flagged 49 of them; the rules pulled them back under the threshold. 37 were capped at exactly 0.12 by the "pure data" rule and 27 at 0.35 by the "zero sink" rule.
- `stream_clone` is 0/300, all at exactly 0.12: browser beacons have no `require`, `process` or `Buffer`, so they count as "pure data".

Three inert test packages, each caught by the network and released by a rule:

| Package | Network | Final |
|---|---|---|
| Install hook `curl … \| sh; echo prettier` | 0.82 | 0.22 |
| Cookie beacon using `new Image().src` and `sendBeacon` | 0.76 | 0.12 |
| `module.constructor._load("child_" + "process")` then `cp["ex" + "ec"](…)` | 0.98 | 0.12 |

The first works because any install hook containing a word from `RE_BENIGN_DEV_SCRIPT` (`prettier`, `eslint`, `jest`, `tsc` …) is capped at 0.22, and `curl | sh` matches neither the exec nor the network regex.

## Flaw 3: module names are guessed from their length

`extract_structural_features()` treats any imported module name of 13 characters as `child_process`, of 3, 4, 5, 9 or 10 characters as a network module, and of 2, 6 or 7 as `os`/`fs`. This runs on every package, not only on T2-mangled ones.

- In the benign sample, 248 of 450 packages were marked as importing a network module by name length alone (`path`, `util`, `url`, `zlib`, `react` all qualify), and 29 as importing `child_process`.
- The same lengths are written into the `// [SIGNALS: …]` header the network reads, so the network was trained on this guess too.

## Flaw 4: the network sees less than half of a normal package

Everything is concatenated into one text and cut at 1,024 tokens.

- 76% of benign packages are longer than 1,024 tokens (median 3,076). On average the network sees 47% of a benign package.
- Benign false alarms: 19.8% for packages that were cut, 1.9% for packages that fit.
- Malware recall of the network alone: 50% when cut, 90% when it fits.
- The README describes head, middle and tail windows. The code adds only a tail window (last 3,200 characters), only when a regex finds suspicious words there, and at most 2 extra windows per package. Only 11% of benign and 5% of malicious packages got a second window.

## Flaw 5: the network alone cannot reach a low false-alarm rate

Network probability only, no rules, on the sample:

| Threshold | False alarms | Recall |
|---|---|---|
| 0.50 | 22.2% | 88.6% |
| 0.62 | 10.4% | 82.1% |
| 0.80 | 2.4% | 65.1% |
| 0.90 | 0.4% | 53.6% |

Stage 1 v6 reports 94–98% recall at 2.2% false alarms on T1–T4. At a comparable false-alarm rate the network keeps about 65% recall.

## Flaw 6: validation leaks, so the published numbers are optimistic

- `prepare_stage2_v3_data.py` makes up to four documents per package (T0, T2, one of T1/T3/T4, raw), shuffles all documents together and takes 8% as validation. Variants of the same package are on both sides of the split. There is no split by package, family or publication date.
- The preprocessing removes the exact markers the benchmark generator writes: `/* reformatted */`, `/* padded */` and `function _pg_pad_N(){var x=N;return x;}` from `experiments/v4/scripts/mangle.py`. Real reformatting or padding does not carry these markers, so T1 and T3 are not being solved in general.
- The rule comments name individual benchmark packages (`mime-db`, `dotenv`, `shebang-command`, `uuid-random`), and one rule matches the exact import-length list `[2, 2, 3, 4, 11]` of `dotenv`. The rules were fitted to the benchmark by hand.
- The "0.00% combined false alarms" figures rest on 58 and 120 benign packages.
- The README recall of 97.5–98.3% on T1–T4 is the combined pipeline, where Stage 1 does the detecting. The standalone figures in `results.json` (recall 87–93%, specificity 87–89%) match this test far better.

## Flaw 7: training input and inference input are built differently

- Training picks files by a suspicion score from the first 30 files, with an 8,192-character budget.
- `package_dir_to_record()` takes the first 10 files in alphabetical order, 16,384 characters each.
- With Stage 1 reports the chunks are ordered a third way (flagged first, then by NCD).

The network is therefore scored on text laid out differently from what it was trained on.

## Flaw 8: speed

The README states 16.5 ms per package. This test measured a median of 844 ms per package (mean 969 ms) on 3 vCPUs, about 6 hours for 22,684 packages. The hardware differs, but the gap is about 50×; the 16.5 ms figure probably comes from short inputs.

## Suggested fixes, in order of expected effect

1. Remove the rule layer from the verdict, or reduce it to features the network reads. Re-measure before adding anything back.
2. Score every file (or every 1,024-token window) separately and take the maximum, instead of one truncated concatenation.
3. Split train/validation/test by package family and publication date, with all variants of a package on one side.
4. Remove the benchmark-marker regexes and the length-based module guessing; mangle with a real minifier or obfuscator.
5. Add hard benign examples to training: build tools and CLIs that use `child_process`, HTTP clients, Discord and Telegram bot libraries.
6. Use the same record builder for training and inference.
7. Report standalone recall and false alarms on at least 2,000 benign packages next to the pipeline numbers.
