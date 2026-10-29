---
name: fuzzing-coverage-targeting
description: >-
  Use this skill to decide which fuzz targets a project needs and what shape each harness should take: rank dark reachable regions from coverage data into a diversified portfolio of worthy harnesses (any language), using a worth model, a dark-region taxonomy, harness pattern selection (parser, round-trip, property, stateful, option-matrix, component-API) and overlap-aware diminishing returns with a default cap of 5 pairs per project. Use alongside the language fuzzing skills (which say how to write a harness) and the OSS-Fuzz coverage pipeline (which runs the process).
---

# Fuzzing coverage targeting

This skill is the architect for fuzz target selection: it answers **which** parts of a project are worth harnessing and **what shape** each harness should take. It does not write harnesses (that is the language skills' craft), it owns no process state (that is the coverage pipeline's job), and it issues no commands (that is oss-fuzz-engineer's territory). It is language-agnostic and works standalone whenever a task is about choosing or planning fuzz targets.

## Inputs

- Fresh coverage data: the project's `summary.json` and per-target reports (`reports-by-target`), filtered to the project's own code with build scope verified (a high percentage over a partial build is meaningless).
- Fuzz Introspector data: statically reachable but dynamically unreached functions, optimal targets, blockers.
- The project's source structure: modules, public APIs, state machines, configuration surfaces.
- The language expert's threat model, when composed by the pipeline: attacker-reachable surfaces are the top ranking weight among equals.

## Worth model

Score each dark region as **dark reachable lines × functional importance × bug-class diversity ÷ harness cost**:

- **Dark reachable lines**: lines statically reachable from some harness entry but uncovered, counted as absolute lines, not percentages.
- **Functional importance**: core parsing, transformation, protocol logic and data handling rank high; diagnostics, debug printers, test helpers and build-time code are excluded outright.
- **Bug-class diversity**: memory safety (ASan/MSan/UBSan), logic and assertion violations, hangs and pathological blowups, and leaks. A region rich in several classes outranks a one-class region of equal size.
- **Harness cost**: API complexity, state setup, corpus construction effort.

## Dark-region taxonomy and harness opportunity types

| Dark region type | Typical shape | Example surfaces |
|---|---|---|
| Parser or decoder entry | bytes-in harness | file-format loaders, wire-protocol frames, deserialisers |
| Transformation or codec stage | round-trip or stage harness | encode/decode pairs, colour conversion, filters, re-serialisation |
| Stateful session or protocol object | stateful sequence harness | connection objects, protocol state machines, transactions |
| Internal component API | component harness | regex engines, expression evaluators, container and data-structure operations, maths kernels |
| Configuration or option surface | option-matrix harness | format variants, feature flags, mode switches |
| Encode or serialise direction | round-trip harness | writers and serializers (often dark because only the decode side gets fuzzed) |
| Text or language frontend | structured grammar-ish harness | compilers, template engines, query languages |
| Error and recovery paths | mutation of valid seeds | malformed variants of legitimate inputs |

The taxonomy is the antidote to the "one parser pair per project" outcome: every module shape is a candidate, not only attacker-bytes entry points.

## Harness pattern catalogue

- **Bytes-into-parser** (classic): feed the buffer to the decode entry point; the language skills' craft sections cover it fully.
- **Round-trip**: encode a structured input, decode it back, assert the invariant (identity, or documented lossiness):

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    auto obj = Thing::parse(fdp.ConsumeRemainingBytesAsString());
    std::string out = obj.serialize();            // dark encode direction
    Thing round = Thing::parse(out);              // decoder re-entry
    if (obj != round) abort();                    // invariant: stable round-trip
    return 0;
}
```

- **Property or invariant / differential**: check a documented property of one implementation (cheap: commutativity, idempotence, bounds, canonical-form equality) or compare against a reference implementation (expensive but powerful).
- **Stateful sequence**: build a session object, then drive N API calls from the fuzzed bytes; required for protocol and connection logic that no single call exercises:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    Session s;                                     // state machine under test
    while (fdp.remaining_bytes() > 0) {
        uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, Session::kMaxOp);
        std::vector<uint8_t> arg =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<int>(0, 64));
        s.step(op, arg);                           // ignore documented errors
    }
    return 0;
}
```

- **Option or configuration matrix**: consume small values as option flags and mode switches before the payload so one target sweeps many compiled paths cheaply; pair with a dictionary of option names.
- **Component API**: call the internal module through its intended API with typed, bounded parameters; the language skills' legitimate-input requirement applies (construct valid objects; never feed raw bytes where a struct is expected).

## Portfolio construction

1. Enumerate dark regions from the inputs; classify each by the taxonomy; score each by the worth model.
2. Apply the security weighting: attacker-reachable surfaces rank first among equals; functional dark logic is fully worthy; diagnostics, logging, printf-style output, test helpers and build-time code stay excluded.
3. Produce a **ranked multi-target list** expected to yield several focused harnesses rather than one or two; a single-target list is a smell that the taxonomy was not applied. If honest triage finds nothing worthy, say so: zero worthy targets is a valid outcome, and inventing a trivial pair to hit a one-pair floor is forbidden. The declaration must be proven, not asserted: list the top rejected regions with their numbers and the reason each fails the worth model.
4. Selection is iterative with diminishing returns, executed by the pipeline with its coverage ledger: after each accepted pair, re-rank the remaining targets by **incremental** worth (projected gains minus already-covered ground). A pair whose gains mostly overlap already-accepted coverage is redesigned toward different dark regions, folded into standalone corpus work, or dropped, with the numbers recorded.
5. **Default cap: at most 5 pairs per project** (fuzzer pairs plus the standalone corpus pair; a `-build-fix` pair does not count against the cap), unless the user raises or lowers the threshold in their prompt.
6. **Work the ranked list top-down until the rules are exhausted.** Worth is measured per project and never compared across projects: in a multi-project batch, a second pair for project A competes only with A's own remaining dark regions, never with project B's candidates, and spreading one pair per project is an anti-pattern. A single delivered pair is only the floor for a project's delivered status, never a stopping point. Stop a project's loop only on one of: **(a) worth exhaustion**, the remaining marginal worth is genuinely low, documented with numbers; **(b) the cap**; or **(c) budget exhaustion**, when time or build budget truly runs out. Budget bounds ordering and depth only, never worth: record un-attempted worthy targets as "pair N of project X: worth rationale written, not yet attempted", never as a worth decision, and never drop a target as unworthy for budget reasons.

## Non-goals

- No harness writing: the language skills own craft and idioms.
- No process, sequencing, acceptance or state: the coverage pipeline owns the manifest, the ledger and every decision.
- No infrastructure commands: oss-fuzz-engineer owns `infra/helper.py` usage and report fetching.
