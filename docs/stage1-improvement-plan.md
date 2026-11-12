# Stage 1 improvement plan

Ideas for improving the compression scanner over about three months, collected on 2026-11-12. Nothing here is implemented or measured yet. Paper titles and years are from memory: check each one before citing it.

## Where Stage 1 stands

- Known mode (v6) on the T1–T4 benchmark: 94–98% recall at 2.2% benign flagged. There is little room left on this benchmark, and more tuning on it risks fitting the benchmark.
- The room is outside it. Known gaps:
  - `mal_newver`: 125/200 (62.5%) in the validation sample. New versions often move the attack into an install script with a new endpoint.
  - Real obfuscators and bundlers are untested; T1–T4 are transforms from `mangle.py`.
  - The false-alarm figure rests on a small benign set.
  - The 20,135-package test sets were only sampled (10–20 per category).
  - New mode's primitive channel is keyword matching, so ordinary code that uses `child_process` plus network can trigger it.
  - A family that is not in the references is invisible to known mode by design.

## 1. Measure first

Without these, it is not possible to tell where the ceiling is.

- Scan the full `known` and `new` test sets, all categories.
- Build a held-out benign set of several thousand packages, never used as a reference or for tuning.
- Split by time: references from before a date, test packages from after it.
- Test real tools: `javascript-obfuscator`, `terser`, and bundled output from webpack or esbuild.
- Check for leakage: no test package name or code shape may appear in the references.

Papers:
- Pendlebury et al., "TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time" (USENIX Security 2019)
- Arp et al., "Dos and Don'ts of Machine Learning in Computer Security" (USENIX Security 2022)

## 2. One mode for known and new packages

The scanner cannot know in advance whether a package belongs to a known family, so the user should not have to choose a mode.

- Compute every signal in one pass per chunk: raw NCD, normalised NCD, benign NCD, behavioural primitives.
- Decide in tiers:
  - **known**: the v6 rule as it is (0.70 raw, 0.65 normalised, 0.50 install scripts, with the benign margins);
  - **new**: not a known hit, but raw NCD at or below 0.50 or the primitive rule fires;
  - **clean**: neither.
- Apply the benign veto to the new channel too. New mode has no `-B` today, and combining the modes adds their false alarms.
- Write the tier into the report, for example `"verdict": "known" | "new" | "clean"`. A known hit can stand alone; a new hit is what Stage 2 should review.
- Test: scan the `known` set, the `new` set and the held-out benign set with the combined mode and compare with each single mode. Recall becomes the union of both modes; so do false alarms unless the veto holds them down.

## 3. Compare with the previous version

Probably the largest gain. It targets `mal_newver` and the `compromised_lib` samples that are still to collect.

- Score what changed between a package and its previous release, not the whole package.
- A small malicious addition to a large benign library is diluted in the whole package and stands out in the diff.

Papers:
- Garrett et al., "Detecting Suspicious Package Updates" (ICSE-NIER 2019)
- Vu et al., "LastPyMile: Identifying the Discrepancy between Sources and Packages" (ESEC/FSE 2021)
- Scalco et al., "On the Feasibility of Detecting Injections in Malicious npm Packages" (ARES 2022)

## 4. A better view of the code

The normalised view is lexical (identifiers to `I`, strings to `S`, numbers to `N`). Stronger obfuscation changes structure, not only names.

- Parse to an AST (for example with tree-sitter), normalise there, and compress a serialised AST or token-type stream.
- Add a de-obfuscation pre-pass: constant folding, string-array unpacking, dead-code removal. This extends the base64 and hex decoding already in place.
- Score slices around sensitive calls: only the code that flows into `child_process`, network or file APIs.

Papers:
- Fass et al., "JaSt: Fully Syntactic Detection of Malicious (Obfuscated) JavaScript" (DIMVA 2018)
- Fass et al., "JStap: A Static Pre-Filter for Malicious JavaScript Detection" (ACSAC 2019)
- Moog et al., "Statically Detecting JavaScript Obfuscation and Minification Techniques in the Wild" (DSN 2021)
- Sejfia and Schäfer, "Practical Automated Detection of Malicious npm Packages" (ICSE 2022, Amalfi)
- Huang et al., "DONAPI: Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping" (USENIX Security 2024)

## 5. The distance

- Check compressor window and block-size effects against the 64 KiB dictionary and 8 KB chunks.
- Short-chunk bias: NCD is unreliable on small inputs, which is why chunks under 256 bytes are ignored. A length-dependent threshold may recover some of them.
- Try the successors of LZJD and other compression distances.
- Use the k nearest references instead of the single closest: several close references from one family are stronger evidence than one accidental match.
- Compressor comparison (xz, zstd, PPMd) and chunk size (4, 8, 16 KB) are already on the evaluation list in the README.

Papers:
- Cebrián et al., "Common Pitfalls Using the Normalized Compression Distance: What to Watch Out for in a Compressor" (2005)
- Raff and Nicholas, "An Alternative to NCD for Large Sequences, Lempel-Ziv Jaccard Distance" (KDD 2017)
- Raff and Nicholas, "Malware Classification and Class Imbalance via Stochastic Hashed LZJD" (2017)
- Raff et al., "A New Burrows Wheeler Transform Markov Distance" (AAAI 2020)
- Jiang et al., "'Low-Resource' Text Classification: A Parameter-Free Classification Method with Compressors" (ACL Findings 2023), together with the published critiques of its evaluation

## 6. The reference sets

Observation so far: every time the malware and benign reference sets grew, detection improved and false alarms dropped. Stage 1 is a nearest-neighbour detector, so its bottleneck is coverage.

### Learning curve

- Scan one fixed test set with 10%, 25%, 50% and 100% of the references and plot recall and false alarms against reference size.
- Still rising at 100%: collecting more data is the cheapest improvement.
- Flat: data is used up, and the techniques in the other sections are where the gain is.

### Rules while growing

- Grow malware and benign references together. More malware references alone should raise false alarms; the benign set pulls them back down.
- Watch for leakage: the larger the reference set, the more likely a test package or another version of it is also a reference.
- Cost grows too: v1 already peaks at 1.74 GB with a 43 s load.
- Data cannot fix a family that appears after the references were collected.

### Selection

- Pick representatives per family (medoids from clustering) instead of static ratios. This can give the accuracy of a much larger set at the cost of a small one, and removes noisy references.

### More malware sources

- Backstabber's Knife Collection (Ohm et al., 2020), MalwareBench, sample zips over 1 MiB, `compromised_lib` samples.

### Benign references from the npm registry

The full registry archive is over 20 TB. Do not mirror it; sample it.

- Latest version only: old versions are near-duplicates.
- Mix the most-downloaded packages with a random draw from the long tail.
- Cap the tarball size, as with the 1 MiB limit for malware.
- Skip packages with no JavaScript.
- Deduplicate while collecting: drop a package whose chunks have all been seen.
- Fetch tarballs one at a time from `registry.npmjs.org` with parallel connections; take names and metadata from the registry's replication feed and download counts from npm's downloads API.
- Only take packages that are a few months old and have real download numbers, so that malware not yet taken down does not become a benign reference.
- Record every publish date, for the time split.
- Grow in steps (5k, 10k, 25k, 50k, 100k packages) and re-run the same test set each time. Stop when false alarms stop dropping.
- Rough size estimate, not measured: 50,000–100,000 packages should be a few GB to a few tens of GB.

## 7. Robustness against an attacker who knows the design

- Abusing the benign veto: can malicious lines interleaved inside a copy of a popular library make the chunk closer to benign than to malware?
- Padding beyond what repeat collapsing removes.

Paper:
- Fass et al., "HideNoSeek: Camouflaging Malicious JavaScript in Benign ASTs" (CCS 2019)

## 8. Context for the write-up

- Ohm et al., "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks" (DIMVA 2020)
- Ohm et al., "SoK: Practical Detection of Software Supply Chain Attacks" (ARES 2023)
- Ladisa et al., "SoK: Taxonomy of Attacks on Open-Source Software Supply Chains" (IEEE S&P 2023)
- Duan et al., "Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages" (NDSS 2021)
- Baseline: GuardDog on the same test data.

## Suggested order

| Weeks | Work |
|---|---|
| 1–2 | Measurement: full sets, held-out benign, time split, real obfuscators, learning curve |
| 3–5 | Version-diff scoring |
| 6–8 | AST view and de-obfuscation pre-pass |
| 9–10 | Distance and k-nearest experiments, reference selection, benign growth steps |
| 11–12 | Robustness tests, single combined mode, final numbers against GuardDog |

## When to stop

Stage 1 has reached its practical ceiling when a new technique moves recall or false alarms by less than the noise of the test set on the time-split data, and the learning curve is flat.
