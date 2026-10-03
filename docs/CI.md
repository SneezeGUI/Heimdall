# Continuous integration

Heimdall deliberately ships **no CI workflows**.

The CodeQL workflow inherited from Ragnar referenced
`.github/codeql/codeql-config.yml`, which upstream deleted
(`ea056a93`). Every push therefore failed instantly and mailed the operator a
"Run failed: CodeQL" — one per commit. Even fixed, CodeQL is the wrong tool
here: this project *is* an authorized-security-testing codebase, with
deliberate exploit probes (`actions/exploit_engine.py::POC_CATALOGUE`), attack
connectors and Nuclei integration. A static analyser that flags exploit code as
a finding will never go quiet.

Remaining upstream workflows are scoped and harmless:

* `docker-publish.yml` — only on `v*` tags and published releases
* `build-rusense-flasher.yml` — only on `View`/`main` with a path filter

If a workflow is ever added back, it must not run on every push to `main`
without a path filter. Silent CI is fine; CI that mails the operator on every
commit is not.
