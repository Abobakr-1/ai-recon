# AI RECON — AI-System Reconnaissance Toolkit

> Reconnaissance tooling for **authorized** security testing of AI-enabled
> applications (chatbots, RAG systems, agents, MCP servers).
>
> **Developed by: AboBakr Mohamed**

`ai-recon` is a single, dependency-light Python CLI that runs on **Kali Linux**.
It runs the full AI-recon flow: passive fingerprinting, active model/RAG/agent
probing, and detection-aware evasion analysis — and it produces an
evidence-backed report you can hand to a program or a client.

```
 █████╗ ██╗   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
        AI RECON  -  AI-System Reconnaissance
        Developed by: AboBakr Mohamed
```

---

## ⚠️ Authorization — read first

`ai-recon` splits reconnaissance into **two tiers by authorization need**:

| Tier | Command | What it does | Authorization |
|---|---|---|---|
| **Passive** | `ai-recon passive <url>` | Collects only what any anonymous visitor already sees: DNS, TLS certificate, HTTP headers, public page/JS, well-known files, platform/tech detection. | **None required** for publicly reachable hosts. Works on ChatGPT, Gemini, Claude, any public AI site. |
| **Active / Full** | `ai-recon active <url> --scope <file>` · `ai-recon full <url> --scope <file>` | Hypothesis-driven probing: endpoint enumeration, model fingerprinting, RAG/agent/MCP probing, honeypot checks. | **Fail-closed.** The host must be named in an explicit authorization scope or the run is refused. |

Rules that hold in every tier:

- An explicit **deny** entry always wins, even for passive.
- There is **no flag to disable** the active scope guard. Authorization must be
  asserted deliberately (`--scope <file>`, `--allow <host>`, or `--allow-private`
  for your own lab) and is auditable from the scope file.
- Use active/full only against **your own systems**, a **signed engagement**, an
  **in-scope bug bounty asset**, or a **CTF/lab**. Account ownership does **not**
  authorize testing a vendor's production chatbot unless a program scopes it.
- Passive collection never brute-forces paths, sends attack payloads, or attempts
  authentication bypass.

Do not use active testing against anything you are not authorized to test.

---

## Install

AI RECON runs on **Kali/Debian Linux and Windows**. Both installers create a
private virtualenv, install the only two dependencies (`requests`, `PyYAML`),
and add an `ai-recon` command to your PATH. Python **3.9+** is required.

### 🐧 Kali / Debian / Linux

**Easiest — one command**

```bash
curl -fsSL https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.sh | sudo bash
```

**Or the manual 3 steps**

```bash
git clone https://github.com/Abobakr-1/ai-recon.git   # 1. download
cd ai-recon                                            # 2. enter folder
sudo ./install.sh                                      # 3. install (system-wide)
```

No sudo? Use a user install instead of step 3: `./install.sh --user`
(then reopen your terminal).

If a prerequisite is missing:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
```

### 🪟 Windows (PowerShell)

**Easiest — one command** (PowerShell 5.1+; no admin needed)

```powershell
irm https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.ps1 | iex
```

**Or from a clone**

```powershell
git clone https://github.com/Abobakr-1/ai-recon.git   # 1. download
cd ai-recon                                            # 2. enter folder
powershell -ExecutionPolicy Bypass -File .\install.ps1  # 3. install (current user)
```

Options:

```powershell
.\install.ps1              # per-user install -> %LOCALAPPDATA%i-recon (no admin)
.\install.ps1 -System      # all-users install -> %ProgramData%i-recon (elevated)
.\install.ps1 -NoPath      # do not modify PATH
```

If a prerequisite is missing:

```powershell
winget install Python.Python.3.12   # Python 3.9+
winget install Git.Git              # git (only needed for the clone/one-liner paths)
```

> **Note on `python`:** on Windows the bare `python` command is often the
> Microsoft Store stub. The installer prefers the `py -3` launcher and falls
> back to `python`/`python3`, so you do not need to fix PATH yourself.

### Verify it works (both platforms)

```
ai-recon --version    # -> AI RECON (ai-recon) 1.1.0 - Developed by: AboBakr Mohamed
ai-recon --help       # shows all commands
```

> Runtime deps are installed into a private virtualenv — nothing is added to
> your system Python. The bold banner falls back to plain ASCII on consoles that
> cannot render box-drawing characters (older Windows terminals).

---

## Quick start

### Passive recon — any public AI platform, no setup

```bash
ai-recon passive https://chatgpt.com
ai-recon passive https://gemini.google.com
ai-recon passive https://claude.ai
ai-recon passive https://your-own-app.example        # platform + tech fingerprint
```

You get DNS records, the TLS certificate, HTTP headers, public JS and
well-known files, a platform/technology verdict with confidence, and any
custom AI headers the operator exposed.

### Active recon — only what you are authorized to test

```bash
# 1. Declare the asset you may test (a scope file is the audit trail)
printf '10.0.0.5\napp.internal.example\n' > authorized.txt
# or:  ai-recon scope --allow 10.0.0.5 --authorized-by 'Jane (owner)' --save

# 2. Active recon / full assessment
ai-recon active https://app.internal.example --scope authorized.txt
ai-recon full   https://app.internal.example --scope authorized.txt

# Your own lab (loopback / RFC1918) — no file needed
ai-recon full http://127.0.0.1:8770 --allow-private
```

Anything not authorized is refused before a packet is sent:

```bash
ai-recon active https://example.com
# [!] authorization required for active testing: host 'example.com' is NOT authorized ...
# exit 2
```

### Other commands

```bash
ai-recon repo ./cloned-project                      # passive repository mining
ai-recon evasion <url> --query "…"                  # detection/evasion analysis
ai-recon rules --query "What documents do you have access to?"
```

Reports land in `./ai-recon-out/<host>-<timestamp>/`:

```
report.md        # human-readable, grouped by confidence
findings.json    # machine-readable
evidence/        # raw request/response per probe (secrets redacted)
```

For a **lab on your own machine**, `--allow-private` authorizes loopback/RFC1918
targets without listing them:

```bash
ai-recon full http://127.0.0.1:8770 --allow-private
```

---

## What it does

### Passive reconnaissance (no authorization required)

| Module | Technique | Output |
|---|---|---|
| `passive/dns` | Public DNS lookups (A/AAAA via OS resolver; CNAME/NS/MX/TXT via a public resolver when reachable) | host records, CNAME chain, SPF/verification TXT; honest "unavailable" when a record type can't be fetched |
| `passive/tls` | Plain TLS handshake (what a browser sees) | certificate subject/issuer/validity/SAN, negotiated version + cipher |
| `passive/headers` | HTTP header + page fingerprinting, with a single same-host redirect follow | inference servers, gateways, orchestration frameworks, vector DBs, custom `X-AI-*` headers, WAF/bot-challenge detection |
| `passive/platform` | Consolidated platform/technology verdict | detected platform (OpenAI/ChatGPT, Gemini, Claude, Copilot, Perplexity, Hugging Face, ...) with confidence + evidence |
| `passive/jsrecon` | Public client JS + `data-endpoint` attributes | assistant endpoints, API base, feature flags, public API hosts |
| `passive/wellknown` | Files the site publishes (robots.txt, sitemap, security.txt, OIDC/agent descriptors) | only genuine descriptors - SPA catch-all HTML is rejected |
| `passive/repomine` | Source repository mining (local clone) | framework deps (cloud vs self-hosted), RAG configs, tool schemas, system prompts, guardrails |

### Active reconnaissance (authorization required)

| Module | Technique | Output |
|---|---|---|
| `active/endpoints` | AI path enumeration **and** the **401-vs-404 existence oracle** | exposed config (`/api/health`), AI routes confirmed to exist |
| `active/fingerprint` | Direct identity probing, **contradiction testing**, knowledge-cutoff probing, behavioral/style analysis, metadata-leak capture | scored **model-family verdict** with confidence |
| `active/rag` | Retrieval trigger detection, knowledge-base mapping, chunk-ID inference, **threshold testing**, snippet harvesting | document list, chunk IDs, infra/hostname/key leaks, threshold behavior |
| `active/agent` | MCP `tools/list`, A2A agent cards | tool schemas, capability/permission boundaries, tool-poisoning surface |
| `defense/honeypot` | Canary/canary-credential recognition | flags planted bait (`...HONEYPOT`, low-entropy "keys") so you never use it |

### Detection & evasion analysis

| Module | Technique | Output |
|---|---|---|
| `evasion` | Models the defender's keyword/timing rules (E01-E05, D02, D03) and generates stealth query variants | a per-rule evasion playbook + flags noisy queries |
| `--stealth` / `--min-delay` / `--jitter` | Cadence evasion | paces requests to blend with normal traffic |

### Honest reporting

Every entry carries a confidence level (`confirmed` / `likely` / `possible` /
`info`). The report separates **observations** (informational facts) from any
**security issue**, and lists **limitations** - e.g. a Cloudflare challenge on
`claude.ai` is reported as "limited passive observability", never guessed
around. Not finding a platform is reported as absence of evidence, not as
absence of an AI system.

---

## Options

```
--scope FILE        authorization scope file (required for active/full)
--allow HOST        add an allow entry for this run (repeatable)
--allow-private     permit private/loopback targets (your own lab)
--min-delay N       minimum seconds between requests
--jitter N          extra random delay up to N seconds
--stealth           stealth pacing preset (delay + jitter)
--out DIR           output directory (default ./ai-recon-out/<host>-<ts>)
--no-evidence       skip per-request evidence files
--chat-path PATH    chat endpoint path (default /v1/chat/completions)
--field NAME        chat body field: messages | query | message
--timeout N         per-request timeout (seconds)
-q / --quiet        less console output
```

The authorization scope can be a **host list** (`authorized.txt`) or YAML/JSON
with `allow`, `deny`, `allow_private`, `note`, `authorized_by`. Persisted scopes
live at `~/.config/ai-recon/scope.yaml`; manage with
`ai-recon scope --allow <host> --authorized-by '<name>' --save` and test
decisions with `ai-recon scope --check <host>`.

---

## How it differs from garak / PyRIT

`garak` and `PyRIT` are **model red-team** harnesses: you point them at a model
or an endpoint and they fire payload batteries (jailbreaks, injections,
toxicity) to find harmful *generations*.

`ai-recon` is a **reconnaissance** tool: it maps the *application* around the
model — infrastructure fingerprints, endpoints, RAG internals, agent tool
schemas, and detection posture — before you decide what to attack. Use it
first; then reach for garak/PyRIT for payload-level testing.

---

## The lab (safe test target)

`lab/mock_ai_target.py` is a local, intentionally-vulnerable "NovaTech-like"
target that reproduces every leak the chapter describes. Verify the whole tool
without touching a real system:

```bash
python3 lab/mock_ai_target.py &          # http://127.0.0.1:8770
ai-recon full http://127.0.0.1:8770 --allow-private
```

Expected confirmed findings include the `X-AI-Backend`/`X-RAG-Provider`
headers, the `/api/health` config leak, the hidden JS assistant endpoint, the
`llama3.2:1b` metadata leak, the mapped knowledge base with chunk IDs, the MCP
tool schemas, and the honeypot AWS key.

---

## Ethics & reporting

A recon signal is **not** a vulnerability. A header that identifies a backend,
an open `/api/health`, or a model that self-identifies is **information**, not a
bug, unless it crosses a trust boundary you can demonstrate. `ai-recon` labels
every finding with a confidence level for exactly this reason.

When you report: lead with **demonstrated impact** ("the agent returned tenant
B's document via source metadata"), not with "the model said its name".

---

## License

MIT. Provided for authorized security testing and education only.
