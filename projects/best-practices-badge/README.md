# OpenSSF Best Practices Badge — OSS-Fuzz integration

The [OpenSSF Best Practices Badge](https://www.bestpractices.dev/) is the
Linux Foundation / OpenSSF's official security-badging system for free and
open source software. Over 10,000 open source projects have registered,
including critical infrastructure such as the Linux kernel, curl, OpenSSL,
Node.js, and Kubernetes. The badge criteria are a widely-used
scheme for demonstrating secure development practices.
The software supports both its own "metal" criteria (passing, silver, gold)
derived from secure OSS practices, and the "baseline" criteria
(baseline-1, baseline-2, baseline-3) derived from recommendations from
regulations, government guides, and similar materials on how to secure
OSS. We generally encourage projects to do both eventually.

## Current Fuzz targets

| Target | Source | What it exercises |
|---|---|---|
| `fuzz_url_validator` | `app/validators/url_validator.rb` | Custom URL regex, percent-decode pipeline, UTF-8 encoding validation |
| `fuzz_markdown_processor` | `app/lib/markdown_processor.rb`, `app/lib/invoke_commonmarker.rb` | Markdown fast-path regexes (ReDoS), CommonMarker HTML generation, URL-protocol sanitization (XSS prevention) |

Harnesses live in `script/fuzz_*.rb` in the project repository and are
referenced directly by `build.sh` so they stay in sync with source changes.

We expect this to grow over time; this is a starting point.

## Fuzzing stack

- **Language:** Ruby
- **Library:** [Ruzzy](https://github.com/trailofbits/ruzzy) (Trail of Bits)
- **Engine:** libFuzzer
- **Sanitizers:** AddressSanitizer, UndefinedBehaviorSanitizer

## Reporting vulnerabilities

Use the [GitHub private vulnerability reporting form](https://github.com/coreinfrastructure/best-practices-badge/security/advisories/new).
