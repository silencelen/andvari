# codeql-kotlin-tripwire fixtures (H40)

Each directory is a stand-in for `.github/workflows/`; `scripts/ci/codeql-kotlin-tripwire.test.sh`
runs the tripwire over every `fail-*` dir and expects exit 1, over every `pass-*` dir and the live
`.github/workflows/` and expects exit 0. The four `fail-*` shapes named in the H40 finding are the
ones the original one-file/one-spelling awk let through: the list-form matrix, a second job that
hands `languages:` straight to the init action, CodeQL's `java` alias, and a separate workflow
file. `fail-autobuild-not-allowed` pins the positive assertion — a real build-mode is necessary but
not sufficient; the language must also be added to `ALLOWED_LANGUAGES` on purpose.

These files are never run by GitHub Actions: the fixtures live under `scripts/ci/`, not
`.github/workflows/`.
