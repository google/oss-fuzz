# Dockerfile для Google OSS-Fuzz интеграции Umbrella Protocol.
# Dockerfile for Google OSS-Fuzz integration of Umbrella Protocol.
#
# Этап 9 Hardening, блок 9.6 — OSS-Fuzz onboarding.
# Stage 9 Hardening, block 9.6 — OSS-Fuzz onboarding.
#
# Этот файл — локальный stub в нашем репозитории. Submission в Google OSS-Fuzz
# выполняется через PR в `google/oss-fuzz` repo, где этот Dockerfile помещается
# в `projects/umbrella-protocol/Dockerfile`. Backend coordination + status
# tracking — через Google OSS-Fuzz issue tracker.
#
# This file is a local stub in our repository. Submission to Google OSS-Fuzz
# is via PR to the `google/oss-fuzz` repo, where this Dockerfile is placed at
# `projects/umbrella-protocol/Dockerfile`. Backend coordination and status
# tracking are via the Google OSS-Fuzz issue tracker.

# Базовый образ Google OSS-Fuzz Rust builder. Содержит pre-installed nightly
# Rust toolchain + cargo-fuzz binary, что нужно для libfuzzer-sys 0.4 build.
# См. <https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/>
# § "Project files".
#
# Base image: Google OSS-Fuzz Rust builder. Provides a pre-installed nightly
# Rust toolchain plus the `cargo-fuzz` binary required by `libfuzzer-sys` 0.4.
# See <https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/>
# section "Project files".
FROM gcr.io/oss-fuzz-base/base-builder-rust

# Maintainer хука для OSS-Fuzz issue notifications. Адрес фигурирует в
# project.yaml `primary_contact` — см. SPEC-13-PQ-HYBRID и memory.
# Maintainer hook for OSS-Fuzz issue notifications. The address also appears
# in project.yaml `primary_contact` — see SPEC-13-PQ-HYBRID and memory.
LABEL maintainer="UmbrellaX Security <samuel.vens18@gmail.com>"

# Установить системные deps. На base-builder-rust большинство уже presell;
# git нужен явно для clone.
# Install system deps. Most are present on base-builder-rust; git is pulled in
# explicitly for the clone.
RUN apt-get update && \
    apt-get install --no-install-recommends -y git ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Clone репо в OSS-Fuzz workspace (`$SRC` — стандартная переменная окружения
# OSS-Fuzz, указывает на `/src/`). Используется master branch как канонический
# источник; OSS-Fuzz CI re-pull'ит upstream при каждом build цикле для свежей
# версии (24-часовой кадeнс per Google docs).
#
# Clone the repo into the OSS-Fuzz workspace (`$SRC` — standard OSS-Fuzz env
# variable that points to `/src/`). The master branch is used as the canonical
# source; OSS-Fuzz CI re-pulls upstream on every build cycle to pick up the
# latest revision (24-hour cadence per Google docs).
RUN git clone --depth 1 https://github.com/umbrellax/umbrella-protocol $SRC/umbrella-protocol

# Скопировать build script в workspace location, ожидаемый OSS-Fuzz harness.
# Copy the build script into the workspace location expected by the OSS-Fuzz harness.
COPY build.sh $SRC/

# Workdir для удобства debug — все subsequent команды OSS-Fuzz относительно
# репо. Реальный build path определяется внутри build.sh ($WORK / $OUT).
# Workdir for debug convenience — all subsequent OSS-Fuzz commands are relative
# to the repo. The actual build path is set inside build.sh ($WORK / $OUT).
WORKDIR $SRC/umbrella-protocol
