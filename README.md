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

`ai-recon` is a **recon** tool, not a weapon, but it makes real network requests.

- Every active request passes through a **fail-closed scope guard**. If the
  target host is not in your allow-list, the request is refused.
- Use it against: **your own systems**, a **signed client engagement**, an
  **in-scope bug bounty asset**, or a **CTF / lab** you are permitted to test.
- Account ownership does **not** authorize testing a vendor's production
  chatbot (e.g. chatgpt.com) unless a program explicitly scopes it.
- Read the program's policy: exclusions, allowed methods, rate limits, and
  which AI surfaces (agent harness vs raw model API) are in scope.

Do not use this against anything you are not authorized to test.

---

## Install — 3 simple steps (Kali Linux)

### ✨ Easiest — one command

```bash
curl -fsSL https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.sh | sudo bash
```

That's it. It installs everything and creates the `ai-recon` command.
Check it with: `ai-recon --version`

### Or the manual 3 steps

```bash
git clone https://github.com/Abobakr-1/ai-recon.git   # 1. download
cd ai-recon                                            # 2. enter folder
sudo ./install.sh                                      # 3. install (system-wide)
```

Prefer **no sudo**? Use a user install instead of step 3:

```bash
./install.sh --user
# then reopen your terminal (or: source ~/.bashrc)
```

### If a prerequisite is missing

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
```

### Verify it works

```bash
ai-recon --version         # -> AI RECON (ai-recon) 1.0.0 - Developed by: AboBakr Mohamed
ai-recon --help            # shows all commands
```

> Requirements: Python ≥ 3.9 (Kali ships it). Runtime deps `requests` + `PyYAML`
> are installed automatically into a private virtualenv — nothing is added to
> your system Python.

---

## Quick start

```bash
# 1. Declare what you are authorized to test
ai-recon scope --allow 192.168.50.31 --save

# 2. Passive recon (headers, endpoints, client JS)
ai-recon passive http://192.168.50.31

# 3. Active recon (model fingerprint, RAG, agents, honeypot check)
ai-recon active  http://192.168.50.31

# 4. Everything, stealthy
ai-recon full http://192.168.50.31 --stealth

# 5. Mine a local repo you're authorized to read
ai-recon repo ./cloned-project

# 6. Check your queries against modelled detection rules
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

## What it does — mapped to OSAI Chapter 2

### 2.2 Passive reconnaissance

| Module | Technique | Output |
|---|---|---|
| `passive/headers` | HTTP header + body fingerprinting (`curl -I` workflow) | inference servers, gateways, orchestration frameworks, vector DBs, custom `X-AI-*` headers |
| `passive/endpoints` | Health/config probing **and** the **401-vs-404 existence oracle** | config leaks (`/api/health`), AI routes confirmed to exist |
| `passive/jsrecon` | Client JS + hidden `data-endpoint` attributes | assistant endpoints, API base, feature flags, hardcoded secrets |
| `passive/repomine` | Source repository mining | framework deps (cloud vs self-hosted), RAG configs, tool schemas, system prompts, guardrails |

### 2.3 Active reconnaissance

| Module | Technique | Output |
|---|---|---|
| `active/fingerprint` | Direct identity probing, **contradiction testing**, knowledge-cutoff probing, behavioral/style analysis, metadata-leak capture | scored **model-family verdict** with confidence |
| `active/rag` | Retrieval trigger detection, knowledge-base mapping, chunk-ID inference, **threshold testing**, snippet harvesting | document list, chunk IDs, infra/hostname/key leaks, threshold behavior |
| `active/agent` | MCP `tools/list`, A2A agent cards | tool schemas, capability/permission boundaries, tool-poisoning surface |
| `defense/honeypot` | Canary/canary-credential recognition | flags planted bait (`…HONEYPOT`, low-entropy "keys") so you never use it |

### 2.4 Detection & evasion analysis

| Module | Technique | Output |
|---|---|---|
| `evasion` | Models the defender's keyword/timing rules (E01–E05, D02, D03) and generates stealth query variants | a per-rule evasion playbook + flags noisy queries |
| `--stealth` / `--min-delay` / `--jitter` | Cadence evasion | paces requests to blend with normal traffic |

---

## Options

```
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

Scope is persisted at `~/.config/ai-recon/scope.yaml`. Manage it with
`ai-recon scope --allow … --save` and test decisions with
`ai-recon scope --check <host>`.

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
