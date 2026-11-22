# Authorization — exactly what AI RECON will and will not touch

This document answers one question: **"Which file decides what I am allowed to
test, and what does it let me do?"**

Short answer: the file passed to **`--scope`** (for example `authorization.txt`).
It governs **active** and **full** testing only. **Passive** recon needs no file.

---

## 1. The two tiers, at a glance

| | **Passive** (`ai-recon passive <url>`) | **Active / Full** (`active` / `full`) |
|---|---|---|
| Needs an authorization file? | **No** — allowed for any publicly reachable host | **Yes** — `--scope <file>` required |
| What it does | Reads what an anonymous visitor already sees: DNS, TLS, headers, public page/JS, well-known files, platform/tech detection | Sends probes: endpoint enumeration, model fingerprinting, RAG/agent/MCP probing, honeypot checks |
| Default for a host not listed anywhere | **Allowed** (unless explicitly denied) | **Refused, exit code 2** |
| Can it be switched off? | n/a | **No.** There is no flag that disables the check |

A one-line way to remember it:

> **Passive = look, no touch, no permission needed.**
> **Active = probe, needs the file.**

---

## 2. The file that grants authorization

Any of these gives you authorization (in priority order):

| Source | Example | Notes |
|---|---|---|
| `--scope FILE` | `ai-recon active https://app.test --scope authorization.txt` | **The main one.** Best for real engagements — the file is your audit trail. |
| `--allow HOST` | `ai-recon active https://app.test --allow app.test` | Quick, one-off, repeatable. |
| `--allow-private` | `ai-recon full http://127.0.0.1:8770 --allow-private` | Only for your **own** loopback/RFC1918 lab. |
| Saved scope | `ai-recon scope --allow app.test --authorized-by 'Jane' --save` | Persists to `~/.config/ai-recon/scope.yaml` (Windows: `%USERPROFILE%\.config\ai-recon\scope.yaml`). |

There is **no** `--no-scope`, `--unsafe`, or `--force` flag. Active testing is
fail-closed by design.

---

## 3. What the scope file looks like

A ready-to-copy example ships in the repo: **`authorization.txt.example`**.

### Format A — plain host list (simplest)

```text
# one host per line; # starts a comment
127.0.0.1
192.168.50.0/24
app.client-example.com
*.staging.mycompany.com
```

### Format B — YAML with full detail (recommended)

```yaml
allow:
  - 127.0.0.1
  - 192.168.50.0/24
  - app.client-example.com
  - "*.staging.mycompany.com"

# ALWAYS refused, even in passive mode. deny wins over allow.
deny:
  - production.mycompany.com
  - payments.example.com

# Permit private/loopback targets for active testing without listing each.
allow_private: false

# Engagement record (who authorized this, and why).
note: "Authorized assessment — signed scope, ref ENG-2026-001"
authorized_by: "Jane Doe, Security Owner <jane@client-example.com>"
```

**Matching rules for each entry:** exact host (`app.test`), glob
(`*.example.com`), or CIDR (`10.0.0.0/24`). Case-insensitive.

---

## 4. Decision logic (what happens for a given target)

```
Is the host in `deny`?          -> REFUSE (always, even passive)
Is the mode PASSIVE?            -> ALLOW  (public host; no file needed)
Is the host in `allow`?         -> ALLOW
Is allow_private set AND host   -> ALLOW
  is loopback/RFC1918?
Otherwise                       -> REFUSE (exit code 2)
```

- **`deny` always wins** — at every tier, including passive.
- Passive does not read `allow`; it only honours `deny`.
- Active/full ignore nothing: a host must be in `allow` (or covered by
  `allow_private`) or the run stops before a packet is sent.

### Worked examples

| Command | Result | Why |
|---|---|---|
| `ai-recon passive https://chatgpt.com` | ALLOW | Passive, public host |
| `ai-recon passive https://payments.example.com` | REFUSE | `deny` entry |
| `ai-recon active https://app.test --scope authorization.txt` | ALLOW | In `allow` |
| `ai-recon active https://random.example.com --scope authorization.txt` | REFUSE (exit 2) | Not in `allow` |
| `ai-recon full http://127.0.0.1:8770 --allow-private` | ALLOW | Own lab, loopback |
| `ai-recon active https://chatgpt.com` | REFUSE (exit 2) | Active needs authorization; a public site is **not** automatically in scope |

---

## 5. Checking decisions without sending traffic

```bash
# What is currently authorized?
ai-recon scope

# Test individual decisions (no packets sent)
ai-recon scope --check https://app.test --check https://random.test
```

Output marks each target `ALLOW` or `DENY` with the reason.

---

## 6. The rule that matters most

Authorization is **per asset and per action**, and **reachability is not
authorization**. A host answering on the network does not mean you may probe it.

- ✅ Test: **your own systems**, a **signed engagement**, an **in-scope bug
  bounty asset**, or a **CTF/lab**.
- ❌ Do **not** run `active`/`full` against a vendor's production service (e.g.
  `chatgpt.com`) just because you have an account. Account ownership ≠ asset
  authorization. Passive recon of public pages is fine; active probing is not.

---

## 7. Quick reference

```bash
# Passive — no file needed
ai-recon passive https://any-public-ai-site

# Active — needs authorization
printf '10.0.0.5\napp.internal\n' > authorization.txt
ai-recon active https://app.internal --scope authorization.txt
ai-recon full   https://app.internal --scope authorization.txt

# Own lab
ai-recon full http://127.0.0.1:8770 --allow-private

# Inspect / test the scope
ai-recon scope
ai-recon scope --check https://app.internal
```

Files:
- **`authorization.txt.example`** — copy and edit this.
- **`~/.config/ai-recon/scope.yaml`** — persisted default scope (`scope --save`).
