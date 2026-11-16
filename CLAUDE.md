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

## Agnets Selection based on Jobs

- Orchestartor (Fable 5.2): Plan a Feature, Auth and Payments, Secuirty Audit
- Sonnet 5.5: Building a Feature, Write Tests
- Opus 5.5: FrontEnd & UI, Nasty bug, Code Review
- Haiku 5.5: Searching The Codebase, Renames and Boilerplate

## Running Tests

- Any test requested to be ran on the server by the user must be put it in its own tmux session
