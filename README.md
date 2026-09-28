# Heimdall

> *He never sleeps, and sees a hundred leagues around him by night as well as
> by day. He guards the bridge against the coming threat, and his horn sounds
> before it arrives.*

**Heimdall** is an autonomous homelab security monitor and offensive-security
platform for Raspberry Pi-class single-board computers with an e-ink display.
It scans your network, scores what it finds, attempts authorized credential and
exploit verification, and shows you what matters on the device itself.

Heimdall is a **continuation of the Bjorn lineage** — the project that started
as [Bjorn](https://github.com/infinition/Bjorn) by
[**infinition**](https://github.com/infinition), continued as
[Ragnar](https://github.com/PierreGode/Ragnar) by **Pierre Gode**, and now
carried forward as Heimdall.

---

## Lineage

| Project | Author | Role |
|---|---|---|
| [Bjorn](https://github.com/infinition/Bjorn) | [**infinition**](https://github.com/infinition) | Origin. The original e-ink security-monitor concept. |
| [Ragnar](https://github.com/PierreGode/Ragnar) | **Pierre Gode** | Bjorn's successor. Still independently maintained — see the canonical source. |
| **Heimdall** | **SneezeGUI** | Continuation. Adds an exploit engine, AI credential engine, alert sinks, and more. |

Heimdall is **not** the official Ragnar and does not claim to be. Ragnar
remains at its canonical source. Heimdall keeps both upstream projects' terms
intact (see [`LICENSE`](LICENSE)) and shares bugfixes upstream where
appropriate.

### With thanks to infinition

Bjorn is the reason this project exists. The e-ink security-monitor idea, the
form factor, and much of the codebase descend directly from
[infinition's](https://github.com/infinition) original work. Heimdall stands on
that foundation and credits it fully.

---

## What it does

**Recon.** Continuous nmap-based discovery and version detection on your LAN,
with vulnerability scoring and an incremental scan ledger.

**Verification.** An exploit engine turns CVE findings into *scoped, triaged,
authorized* verification attempts — proof-of-concept probes and Nuclei active
checks, never destructive payloads. Findings land in an auditable JSONL ledger.

**Credential work.** An AI-ranked credential engine tries plausible
`(user, password)` pairs before falling back to wordlist spray, with dead-pair
caching and a hard cap on model calls.

**Alerting.** Pluggable notify sinks — Pushover, ntfy, and generic/Slack
webhooks — so findings reach you where you already are.

**On-device reporting.** Live statistics on the web dashboard *and* on the
e-ink display, so the hardware sitting on your desk is always telling the truth.

**AI, provider-agnostic.** Bring your own OpenAI-compatible endpoint. No
vendor lock-in.

---

## Hardware

Built for the **Raspberry Pi Zero 2 W** class of device with a **Waveshare
2.13" e-Paper HAT** — the reference build is a dual-homed Pi (PoE ethernet +
WiFi) running DietPi.

> **Note on resources.** The full toolchain (nmap + Nuclei + the AI stack) does
> not fit comfortably in 512 MB. A board with 4 GB+ RAM is strongly recommended
> for the scanner role. A Pi Zero 2 W works well as a *display and sensor node*
> fed by a more capable head.

---

## Safety and scope

Heimdall performs **active network scanning and exploitation**. The exploit
engine is off by default and scoped by design:

* **RFC1918 / loopback / link-local / CGNAT / ULA only** by default.
* External targets require an explicit allowlist or `exploit_allow_external`.
* `exploit_allow_all` disables all scope filtering. It is labelled dangerous
  and documented with a no-liability disclaimer.
* Proof-of-concept probes are **verification only** — version and banner
  checks. There are no destructive payloads.

**Use only against systems you own or are explicitly authorized to test.**
See [`docs/EXPLOIT_ENGINE.md`](docs/EXPLOIT_ENGINE.md).

---

## Features

### Exploit engine
Scoped CVE verification with high-value triage, optional AI triage, a
proof-of-concept catalogue, and service-aware Nuclei routing (`http/`,
`network/`, `ssl/`, `dns/`). Results are recorded to an auditable ledger and
surfaced on the dashboard and e-ink display.

### AI credential engine
Ranked, target-aware credential pairs tried before the wordlist cartesian
spray. Caches dead pairs across restarts and caps model calls per service.

### Notify sinks
Pushover, ntfy, and generic/Slack webhooks, fanned out from a single dispatch.

### Display integrations
Exploit statistics and status on the web dashboard and the e-ink panel.

---

## Installing

```bash
git clone https://github.com/SneezeGUI/heimdall.git
cd heimdall
# see docs/ for install guides
```

The installer supports the Raspberry Pi + Waveshare e-Paper configuration.

---

## Development

Heimdall is maintained as a **patch-series fork** of Ragnar:

* New features live in-tree as ordinary files.
* Small changes to upstream's core files are kept as a quilt series under
  [`patches/`](patches/), so upstream sync stays tractable.
* [`scripts/sync-upstream.sh`](scripts/sync-upstream.sh) pulls upstream main
  and re-applies the series, reporting conflicts instead of guessing.

See [`docs/FORKING.md`](docs/FORKING.md) for the maintenance workflow.

---

## License

Distributed under three sets of terms — the original MIT License for
Bjorn-derived portions, Pierre Gode's Supplemental Terms for the Ragnar
Contributions, and SneezeGUI's Supplemental Terms for Heimdall's own additions.
See [`LICENSE`](LICENSE) for the full text and which part governs which code.

In short: free for personal, educational, research, and internal non-commercial
use, with attribution retained. Not for sale as a product.

---

## Contributing

Issues and pull requests are welcome. Please:

* Do not remove attribution to Bjorn or Ragnar.
* Keep the exploit engine's scope gates intact — they are not optional.
* Ship a web UI toggle for any new configuration key; no orphan config.
* Test on real hardware where you can.

**Authorized testing only.**
