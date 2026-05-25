# OSS-Fuzz agent skills

Skills and tooling that let an agent CLI (Gemini CLI or Claude Code) write,
build, and extend OSS-Fuzz fuzzing integrations. The folder ships:

- Six skills that give an agent OSS-Fuzz-specific knowledge.
- `infra/experimental/agent-skills/helper.py`, a wrapper that launches agent
  sessions over one or more OSS-Fuzz projects in parallel.
- `copy_to_global.sh`, an installer that places the skills where your
  agent CLI can find them.

Before running anything in this folder, review the [threat model](#threat-model).
This tooling is experimental and runs agents in unrestricted modes.

## Contents

| Item | Purpose |
|---|---|
| `fuzzing-memory-unsafe-expert/` | Skill: fuzz C/C++ projects |
| `fuzzing-go-expert/` | Skill: fuzz Go projects |
| `fuzzing-rust-expert/` | Skill: fuzz Rust projects (cargo-fuzz) |
| `fuzzing-jvm-expert/` | Skill: fuzz JVM projects (Java/Kotlin/Scala) with Jazzer |
| `fuzzing-python-expert/` | Skill: fuzz Python projects with Atheris |
| `oss-fuzz-engineer/` | Skill: OSS-Fuzz infra workflows (integrate, fix, extend) |
| `infra/experimental/agent-skills/helper.py` | Driver that launches agent sessions per OSS-Fuzz project |
| `copy_to_global.sh` | Installs the skills into `~/.gemini/skills` or `~/.claude/skills` |

See each skill's `SKILL.md` for the detailed guidance the agent receives.

## Prerequisites

- A supported agent CLI installed and on `PATH`:
  [Gemini CLI](https://github.com/google-gemini/gemini-cli) or
  [Claude Code](https://claude.com/claude-code).
- Docker (required by OSS-Fuzz's own `infra/helper.py`, which the agent calls).
- Python 3.
- A local checkout of OSS-Fuzz — `infra/experimental/agent-skills/helper.py`
  resolves the repo root relative to its own location, so run it from this
  checkout.

## Quick start

```bash
# 1. Install the skills into your agent CLI.
./copy_to_global.sh gemini        # or: ./copy_to_global.sh claude

# 2. Confirm the agent CLI is reachable.
gemini --version                  # or: claude --version

# 3. Run a task across one or more OSS-Fuzz projects.
python infra/experimental/agent-skills/helper.py fix-builds open62541 json-c htslib
```

`copy_to_global.sh` **overwrites** any existing skill of the same name in the
target directory.

## How the skills are used

There are two ways the skills get invoked:

1. **Interactively, in your agent CLI.** After `copy_to_global.sh`, the
   skills appear to your agent and are auto-selected when a task matches the
   skill's description. For example, asking the agent to write a Python
   harness will surface `fuzzing-python-expert`. You can use the skills this
   way without ever touching `infra/experimental/agent-skills/helper.py`.

2. **Driven by `infra/experimental/agent-skills/helper.py`.** The helper
   builds task-specific prompts that reference these skills and launches
   non-interactive agent sessions, one per OSS-Fuzz project, in parallel.
   Use this when you want to run the same task across many projects.

The agent makes local changes and writes a per-project report. It does
**not** commit or push — review the diff and reports before you do anything
with the output.

## `infra/experimental/agent-skills/helper.py` commands

Run `python infra/experimental/agent-skills/helper.py <command> --help` for
full flag listings. A summary of the available subcommands:

| Command | Purpose | Example |
|---|---|---|
| `expand-oss-fuzz-projects` | Add new harnesses / improve coverage on existing projects | `python infra/experimental/agent-skills/helper.py expand-oss-fuzz-projects open62541 json-c` |
| `fix-builds` | Diagnose and fix broken project builds | `python infra/experimental/agent-skills/helper.py fix-builds htslib` |
| `run-task` | Run an arbitrary `--task` string per project | `python infra/experimental/agent-skills/helper.py run-task --task "Add a harness for the XML attribute parser" open62541` |
| `add-chronos-support` | Add Chronos support to a project | `python infra/experimental/agent-skills/helper.py add-chronos-support json-c` |
| `integrate-project` | Onboard a new project from a Git URL | `python infra/experimental/agent-skills/helper.py integrate-project https://github.com/org/repo` |
| `clean` | Remove local artifacts from previous agent runs | `python infra/experimental/agent-skills/helper.py clean open62541` |
| `show-prompt` | Print the prompt that would be sent, without launching the agent | `python infra/experimental/agent-skills/helper.py show-prompt fix-builds htslib` |

### Useful behaviors and flags

- **Parallelism.** Sessions run in parallel with `DEFAULT_MAX_PARALLEL = 2`.
  Override with the helper's parallelism flag if your machine can handle
  more concurrent Docker builds.
- **Agent auto-detection.** `infra/experimental/agent-skills/helper.py`
  locates the agent CLI on `PATH` automatically — you do not need to tell
  it whether you are using Gemini CLI or Claude Code.
- **Dry runs.** `show-prompt` prints the exact prompt that would be sent.
  Use it first when trying a new command or task description.
- **Reports and logs.** Each session writes a per-project report locally;
  review these before acting on the agent's changes.

## Typical workflows

**Triage a batch of broken projects**

```bash
python infra/experimental/agent-skills/helper.py show-prompt fix-builds proj1 proj2
python infra/experimental/agent-skills/helper.py fix-builds proj1 proj2
# Review the diff and per-project reports, then commit manually.
```

**Onboard a new project end-to-end**

```bash
python infra/experimental/agent-skills/helper.py integrate-project https://github.com/org/repo
# The agent uses oss-fuzz-engineer plus the appropriate fuzzing-*-expert
# skill for the project's language.
```

**Expand coverage on a project you already maintain**

```bash
python infra/experimental/agent-skills/helper.py expand-oss-fuzz-projects myproj
```

**Run a custom investigation across several projects**

```bash
python infra/experimental/agent-skills/helper.py run-task \
    --task "Investigate why the XML parser harness has low branch coverage \
            and add targeted harnesses for the attribute-parsing paths." \
    open62541 json-c
```

## Threat model

This is experimental code with a deliberately permissive threat model:

- Agents run in "dangerous"/"yolo" modes and will execute untrusted code.
- Running this tooling means running untrusted code in your environment.
- Only run it in a heavily sandboxed environment and on a trusted network.
- This code does **not** run in OSS-Fuzz production services and is not part
  of the tooling that runs our continuous fuzzing of open source projects.
