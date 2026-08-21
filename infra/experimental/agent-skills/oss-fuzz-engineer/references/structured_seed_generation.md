# Structured seed generation

Many fuzz targets parse a structured format: a binary container (ELF, PE,
Mach-O, archives), a network/codec bitstream (MPEG-TS, HEIF, DV), or a text
grammar (assembly, a config/definition language). For these, random bytes
almost never get past the parser's first validity checks (magic numbers,
length fields, checksums), so the fuzzer wastes effort at the entrance and the
deep parsing code stays dark.

A small script that **constructs structurally-valid inputs from scratch** is
the highest-leverage fix: it gives libFuzzer starting points that already pass
the early checks, so mutation explores the real logic. This is far more
effective than a handful of hand-picked sample files, and it is reproducible,
self-contained (no external corpus), and easy to extend.

The canonical example in this repository is
[`projects/vlc/generate_seeds.py`](../../../../../projects/vlc/generate_seeds.py),
which builds MPEG-TS, HEIF, DV, VC-1, CDG and MUS streams from first
principles. Study it before writing your own.

## When to use this

Use a generator script when **coverage shows reachable-but-dark parser code**
and the format is structured. Do not write seeds for code that is already
well covered, or for code that is unreachable for reasons a seed cannot fix
(see "Seed-limited vs harness-limited" below).

## Workflow

1. **Select targets from coverage, not intuition.** Fetch the project's
   public `summary.json` (see [code_coverage.md](code_coverage.md)), parse the
   per-file line percentages, and pick files that are **reachable by an
   existing harness** but sit at low coverage (e.g. < 30%). The production
   report reflects the full accumulated corpus, so it is the authoritative
   "what is still dark" signal.

2. **Construct seeds with a script.** Write a `generate_seeds.py` that emits
   one file per structural variant into a `seeds/<group>/` tree. See
   "Construction techniques" below.

3. **Validate every seed actually parses — and reaches the target.** A seed
   that fails the magic/header check yields *zero* coverage. Check each one
   with the real tool first — e.g. `readelf`/`objdump`/`file` for object files,
   or run the harness binary on it and confirm it is processed rather than
   rejected. Then confirm with a coverage run that the seed actually moves the
   *intended* dark file's coverage; "it parses" is necessary but not
   sufficient.

4. **Wire it into `build.sh`, appending — never replacing.** Run the script at
   build time and **add** the seeds to the existing corpus zips so no original
   seed is lost:

   ```sh
   python3 $SRC/generate_seeds.py $SRC/generated_seeds
   for t in target_a target_b; do
     zip -j $OUT/fuzz_${t}_seed_corpus.zip $SRC/generated_seeds/seeds/<group>/*
   done
   ```

   Copy the script in via the `Dockerfile` (`COPY generate_seeds.py $SRC/`).

5. **Measure: no digression, and quantify the gain.** Run coverage on the
   union (baseline corpus + generated seeds) and confirm it is **>= baseline**
   (appending guarantees this; verify it). To show the seeds reach genuinely
   new code, compare per-file covered-line *counts* against the production
   report: if a generated seed covers more lines of a file than the whole
   production corpus does, those extra lines are provably new (pigeonhole).

6. **Iterate.** Re-read coverage after adding seeds, find the next dark-but-
   reachable branch, and add a variant for it. A few rounds of generate ->
   measure -> target-the-next-gap typically unlock far more than one large
   batch, and keep each change easy to review.

## Construction techniques (from `projects/vlc/generate_seeds.py`)

- **Build the framing exactly.** Honor packet boundaries, box/section length
  fields, and alignment. An off-by-one length usually makes the parser bail
  before the interesting code.
- **Compute checksums in the script.** Formats that carry a CRC/hash reject
  inputs with a wrong one at the header. Implement the checksum (e.g. VLC's
  `crc32_mpeg`) so sections validate and parsing continues.
- **Pack fields with `struct`.** Use explicit endianness and the format's
  reserved-bit conventions, e.g. `struct.pack('>H', 0xE000 | pid)`.
- **Compose small builders.** Build primitives that nest into larger
  structures (packet -> PES -> table -> stream); this keeps the script
  readable and lets you produce many variants cheaply.
- **Emit multiple variants per format.** Different header values, versions,
  optional sections and edge-case sizes hit different branches. One
  parameterized builder over many variants (e.g. one ELF builder over dozens
  of `e_machine` values) can unlock a whole family of per-target backends.
- **Map each seed group to the code it targets** in comments, and note what
  the previous corpus failed to reach — this is the rationale a reviewer needs.
- **Keep seeds small.** libFuzzer favours small inputs; a minimal-but-valid
  seed mutates faster and more usefully than a large one. Build the smallest
  structure that reaches the target code.
- **Be deterministic.** The script runs on every build, so the corpus must be
  byte-identical each time — no timestamps, no RNG, no wall-clock. Vary
  outputs by an explicit index/parameter, not randomness.

## Minimal skeleton

`projects/vlc/generate_seeds.py` is the full reference, but it is large; start
from this shape and grow it. The script takes a corpus root and writes one
file per variant under `seeds/<group>/`:

```python
#!/usr/bin/env python3
import os, struct, sys

def make_widget(variant):
    # Build the smallest structurally-valid input that reaches the target.
    # Honor magic, length fields and checksums; vary by `variant`.
    body = struct.pack('<I', variant)              # ... real structure here
    return b'WDGT' + struct.pack('<I', len(body)) + body

def main(root):
    out = os.path.join(root, 'seeds', 'widget')
    os.makedirs(out, exist_ok=True)
    for v in range(4):                             # deterministic variants
        with open(os.path.join(out, f'widget-{v}.bin'), 'wb') as f:
            f.write(make_widget(v))

if __name__ == '__main__':
    main(sys.argv[1])
```

Wire it into `build.sh` (and `COPY generate_seeds.py $SRC/` in the Dockerfile):

```sh
python3 $SRC/generate_seeds.py $SRC/generated_seeds
zip -j $OUT/fuzz_widget_seed_corpus.zip $SRC/generated_seeds/seeds/widget/*
```

## Per-fuzzer tailoring

Tailor seeds to a specific fuzzer **only when its input contract differs** from
a generic parser:

- A harness gated on a specific target/architecture (it rejects non-matching
  inputs) should receive only matching seeds — anything else is inert.
- A harness that exercises a narrow path (e.g. one that only follows
  separate-debug-file links, not full debug-section dumping) wants seeds for
  *that* path, not the general format.

For the common case — several harnesses that all parse the same format — a
single shared, diverse corpus is correct; splitting it per fuzzer adds
maintenance for no gain (libFuzzer cross-pollinates, and variety helps all of
them).

## Dictionaries

A generator is a natural place to also emit libFuzzer dictionaries
(`$OUT/<fuzzer>.dict`) — magic bytes, tag names, keywords. Dictionaries help
the mutator synthesize tokens it would rarely discover byte-by-byte. VLC emits
both seeds and `dictionaries/*.dict` from the same script.

## Seed-limited vs harness-limited code

Before generating seeds, confirm the dark code is actually reachable by an
existing harness. Some code cannot be reached by any input:

- Options disabled in the harness (a `// dump_x` left commented out).
- Build-time exclusions (e.g. a project built with `--disable-ld` cannot reach
  linker code).
- Format ambiguity where the tool refuses to pick a target and bails.

If the code is harness-limited, no seed will help — that needs a harness
change, which is out of scope for seed work. Note the distinction explicitly
rather than generating seeds that cannot move coverage.

## Measurement pitfalls

- **Validate the header first.** The most common waste is a seed the parser
  rejects immediately; it contributes nothing.
- **Some harnesses break the coverage tooling.** Targets that call `exit()` on
  bad input or leak memory can make libFuzzer's `-merge` coverage step produce
  no profile, especially on small or mixed corpora. This is a tooling
  limitation, not a seed defect; measure such targets on a homogeneous,
  valid-only corpus, and rely on per-seed validation plus the established
  principle that a structured starting corpus helps a previously-unseeded
  harness.
- **Do not mutate a coverage build's `$OUT`.** Manually `rm`/copying files
  inside `build/out/<project>` of a coverage build corrupts its state and
  makes `helper.py coverage` fail for *all* corpora; rebuild if that happens.
  Use `helper.py coverage --corpus-dir <dir>` on a clean build to measure a
  specific corpus.

## When a generator is not enough

A static seed corpus gets the fuzzer past the front door, but for formats with
deep internal structure (length-prefixed trees, checksummed sub-records) the
mutator can still corrupt structure faster than it explores logic. If coverage
plateaus despite good seeds, the next step is structure-aware fuzzing — a
libFuzzer custom mutator, `FuzzedDataProvider` to split the input, or a
grammar/`protobuf`-based mutator. That is harness/tooling work beyond seed
generation, but the seeds you built remain a valuable starting corpus for it.

## Checklist

- [ ] Targets chosen from `summary.json` (reachable, low coverage), not intuition.
- [ ] Confirmed the dark code is seed-limited, not harness-limited.
- [ ] Generator is deterministic and emits small, minimal-but-valid seeds.
- [ ] Each seed validated: it parses *and* moves the intended file's coverage.
- [ ] Seeds appended to existing corpora (never replaced); script copied in via Dockerfile.
- [ ] Union coverage measured: no digression, gain quantified vs production.
- [ ] Each seed group's target code and rationale documented in comments.
