# Using OSS-Fuzz code coverage to find and close gaps

Code coverage is the authoritative signal for *where fuzzing is weak and what
to do about it*. This reference is the playbook: how to find the report, how to
read it, which of its signals answers which question, and how to turn a signal
into a concrete action (new harness / seeds / dictionary / structure-aware
work). Coverage data, not reading the source for "important-looking"
functions, is the source of truth for what needs work.

There are two coverage sources, used for different purposes:

- **Production reports** (public, rebuilt regularly): reflect the *full
  accumulated corpus* for every harness in the project. This is the
  authoritative "what is still dark after all fuzzing to date" signal — use it
  to **choose targets**.
- **Local reports** (you generate them with `helper.py`): reflect only the
  corpus/seeds you give them in a short run. Use them to **measure the effect
  of a change** you just made — a new harness, added seeds, a new dictionary.

Local coverage from a short run with no downloaded corpus will look far worse
than production; never compare a fresh local number against production and
conclude the harness regressed. Compare like with like.

## 1. Find the latest production report

Do **not** guess the date. Every project has a canonical pointer to its most
recent successful report:

```
https://storage.googleapis.com/oss-fuzz-coverage/latest_report_info/<project>.json
```

It returns, e.g. for `curl`:

```json
{
  "report_date": "20260601",
  "html_report_url": "https://storage.googleapis.com/oss-fuzz-coverage/curl/reports/20260601/linux/index.html",
  "report_summary_path": "gs://oss-fuzz-coverage/curl/reports/20260601/linux/summary.json",
  "fuzzer_stats_dir": "..."
}
```

From `report_date` you can build any artifact URL (swap `gs://` for the
`https://storage.googleapis.com/` prefix):

- Machine-readable triage data: `.../reports/<date>/linux/summary.json`
- Human drill-down (per-file, line-level): `.../reports/<date>/linux/index.html`

A report may be missing for a given date if that day's coverage build failed;
`latest_report_info` always points at the last one that succeeded.

## 2. Read `summary.json` — the triage layer

`summary.json` is the standard `llvm-cov export` summary. Its shape:

```json
{
  "data": [
    {
      "totals": { "lines": {...}, "functions": {...}, "regions": {...}, "branches": {...} },
      "files": [
        {
          "filename": "/src/curl/lib/http.c",
          "summary": {
            "lines":     { "count": 1200, "covered": 300, "percent": 25.0 },
            "functions": { "count": 40,   "covered": 8,   "percent": 20.0 },
            "regions":   { "count": 900,  "covered": 150, "notcovered": 750, "percent": 16.6 },
            "branches":  { "count": 600,  "covered": 90,  "notcovered": 510, "percent": 15.0 }
          }
        }
      ]
    }
  ]
}
```

Notes that matter in practice:

- **Filenames are absolute build paths** (`/src/<project>/...`). Match against
  those, and filter out paths outside the project (system headers, deps under
  `/usr`, test files) before ranking — they are noise.
- Iterate `data[0]["files"]`; project totals are in `data[0]["totals"]`.
- Work with **covered-line counts**, not just percentages, when quantifying a
  gain: a big file at 20% has far more dark code than a tiny file at 20%.

## 3. Use the right metric for the question

Each file carries four metrics. They answer *different* questions — using line
% alone (a common mistake) throws away the most useful signals:

| Metric | What it tells you | Use it to decide |
|---|---|---|
| **functions** (`covered`/`count`) | Which functions are *never entered at all*. A file with 0% functions has no harness reaching it. | **Whether a new harness (or new entry point) is needed.** This is the strongest "no fuzzer touches this" signal. |
| **regions** / **branches** | Within functions that *are* reached, which branches stay dark. | **Whether the corpus is the problem**: reached function + dark branches ⇒ seeds / dictionary / structure-aware fuzzing. |
| **lines** | A blended headline number. Conflates "function never called" with "function called but branches dark." | Rough triage / ranking only. Never the sole basis for a decision. |

A file can sit at 60% lines yet have every error-handling branch dark — those
branches are usually the security-relevant paths. A file at 0% functions needs
a completely different fix (a harness) than a file at 90% functions / 30%
branches (better inputs). Line % hides that distinction; functions vs
branches exposes it.

## 4. Triage, then locate

Coverage analysis is two levels:

1. **Triage with `summary.json`** — rank project files by the metric above to
   find *which file* is dark and reachable. Build the blocklist of
   already-covered files here (see the target-selection rule below).
2. **Locate with the HTML report** — open that file's page from `index.html`.
   The HTML shows every line's hit count and highlights uncovered lines and
   dark branches, so you can see *which specific code* inside the file is
   unreached and read the conditions guarding it. `summary.json` gives
   per-file aggregates only; the line/branch-level view lives in the HTML (and,
   for a local run, under `build/out/<project>/report/linux/`).

Reading the guarded-but-dark code is what tells you *why* it is dark — an
early magic/length check the corpus never satisfies (seed work), a branch on
an option the harness hard-codes (harness work), or a function no harness calls
(new harness).

## 5. Target-selection rule (choosing what to work on)

The most common mistake when extending a project is targeting code already
exercised by the production corpus. Before selecting anything:

1. Fetch the production `summary.json` via `latest_report_info`.
2. Build a **blocklist** of files with high coverage — do not write harnesses
   whose primary target lives in a file already ≥ 50% lines *and* with most
   functions covered.
3. Only select targets from files with genuinely low coverage (e.g. < 30%
   lines), and confirm with the functions/branches split what kind of gap it is.

## 6. Fuzz Introspector — reachability-driven gap discovery

`summary.json` tells you what is *covered*; it does not tell you what is
*reachable but unfuzzed*. Fuzz Introspector does. Consult
<https://introspector.oss-fuzz.com> (per-project pages) for:

- **Functions reachable from existing harnesses but never hit** — prime seed /
  input-improvement targets.
- **Unreached functions with high downstream complexity** ("optimal targets"):
  fuzzing one such function transitively covers a large subtree — the highest-
  value place to add a *new* harness.
- **Blockers**: why a reachable function is not being hit.

Use Introspector to answer "where should a new harness go?" and `summary.json`
to answer "which existing file is under-covered?" — they are complementary.

## 7. Generate coverage locally to measure a change

Use the local tooling to validate that a change actually moved coverage.

**Prefer `coverage` for local runs — it is much cheaper and faster.** Build once
with the coverage sanitizer, then generate the report:

```sh
# Build with coverage instrumentation, then report (downloads the public corpus
# by default; add --no-corpus-download to use only local seeds).
python3 infra/helper.py build_fuzzers --sanitizer coverage htslib
python3 infra/helper.py coverage htslib

# Measure one specific corpus (e.g. only your generated seeds vs the baseline)
# on that clean coverage build.
python3 infra/helper.py coverage --corpus-dir <dir> htslib
```

**Use the full `introspector` pipeline sparingly.** It runs the whole chain
(build with ASan → run every fuzzer → rebuild with coverage → extract → build
the Introspector report), which is **heavy and slow** — on a large project it
can take a very long time. Reserve it for **smaller projects**, or when you
specifically need the Fuzz Introspector report rather than plain coverage. When
you do use it, `--coverage-only` skips the Introspector-report build and is the
lighter of its modes:

```sh
# Reasonable only on a smaller project. --out gives a named dir so you can
# compare runs (e.g. before vs after adding seeds).
python3 infra/helper.py introspector --coverage-only --seconds 30 --out htslib-cov-1 htslib
```

See the
[structured seed generation reference](structured_seed_generation.md) for the
full measure-the-gain workflow (per-file covered-line comparison, the
pigeonhole argument that new lines are genuinely new) and the measurement
pitfalls (never mutate a coverage build's `$OUT`; some harnesses break
`-merge`).

## 8. Signal → action

Tie the reading back to a concrete next step:

| Coverage signal | Likely cause | Action |
|---|---|---|
| File at ~0% functions, but reachable in production | No harness exercises it | Add a **new harness** targeting its public entry point (confirm with Introspector it is reachable and worthwhile). |
| Functions covered, but regions/branches largely dark | Corpus never produces inputs valid/varied enough | **Seeds** (structured generation) and/or a **dictionary**; if structure is deep, structure-aware fuzzing. |
| Dark and *no* harness input can reach it (option hard-coded off, build-time exclusion) | Harness-limited | **Change the harness** (set up state / enable the path), or note it as out of scope for seed work. |
| High coverage already (on the blocklist) | Already well fuzzed | Do **not** target it — pick a different file. |

Always give a written rationale for each chosen target: the metric that flagged
it, whether it is seed- or harness-limited, and the expected class of bug — and
after the change, re-measure to confirm the gain and that nothing digressed.
