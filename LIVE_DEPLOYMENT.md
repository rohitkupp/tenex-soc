# Using the live deployment

A step-by-step guide to the hosted version of the Tenex SOC Analyst pipeline — what to open,
what to sign in with, what to upload, and what you should see happen.

There is nothing to install. No Docker, no clone, no Anthropic API key. If you would rather run
the whole stack on your own machine, that is [`LOCAL_SETUP.md`](LOCAL_SETUP.md) instead; this
document is the five-minute path.

> If you just want the link and the credentials, jump to [The short version](#2-the-short-version).
> The rest explains what each step does and what to do when something looks wrong.

**Live now.** Verified 2026-08-19 — `GET /api/health` returns
`{"status":"ok","llm_enabled":true,"email_verification_enabled":true}` with `postgres` connected
and `pgvector: true`.

---

## 1. What you need before you start

| | |
|---|---|
| **A browser** | Any modern one, with cookies allowed for the site. The session is an httpOnly cookie; the app proxies `/api/*` through its own origin specifically so that cookie stays first-party. |
| **A log file to upload** | The five single-scenario logs attached to the email, also in the repo at [`backend/data/demo5_tiny/`](backend/data/demo5_tiny/). Start with `scenario_c2_beaconing.log`. |
| **Time** | About **1 minute** to sign in and upload, then **10–15 minutes** for the analysis to finish. Unattended — everything up to triage is browsable within the first minute. |
| **Nothing else** | No API key. The deployment carries its own, and `llm_enabled: true` on `/api/health` is how you can confirm that from outside. |

### This is a shared demo instance — two things follow from that

**One tenant, one account.** Everyone signs in as the same demo user, so every analysis in the
list is visible to everyone else looking at it. If you find incidents you did not create, that is
someone else's upload, not a bug. Please do not upload anything real or sensitive; the logs
shipped with this project are synthetic.

**Triage spends real money on someone else's key.** There is no offline mode — `DEMO_MODE` was
deliberately removed, so every upload makes live Anthropic API calls. This deployment runs
**Claude Sonnet 5**, where one triaged incident has measured roughly **$0.40–$1.60**, and a run is
capped at **15 incidents** (`MAX_TRIAGE_INCIDENTS` in
[`deploy/gcp/compose.prod.yml`](deploy/gcp/compose.prod.yml)). The recommended demo log produces
5 incidents and costs about $3.

So: **the five logs in `backend/data/demo5_tiny/` are the right thing to upload here.** The multi-megabyte logs in
`backend/data/samples/` are both expensive (27 incidents, ~$20) and, as of the current frontend,
not uploadable through the hosted UI at all — see [Troubleshooting](#6-troubleshooting).

If the Anthropic account runs dry mid-run, the triage stage takes a non-retryable HTTP 400 and the
analysis is marked `failed`. Verdicts already produced are kept and stay browsable; the run does
not resume on its own.

---

## 2. The short version

1. Open **https://tenex-soc.vercel.app**
2. Sign in:

   ```
   demo@tenex.local
   tenex-demo-password
   ```

3. On the Analyses page, click **Click to browse** and pick
   **`backend/data/demo5_tiny/scenario_c2_beaconing.log`** in the file picker. Every log this
   deployment is meant to run comes from that one directory —
   [`backend/data/demo5_tiny/`](backend/data/demo5_tiny/), five files, also attached to the email.
4. Watch the pipeline run. Parse → enrich → detect → correlate finish in well under a minute;
   triage is the long pole at roughly 3 minutes per incident.

That log is 101 lines, 6 users, 3 days — 55 of those lines are a C2 beacon. It yields
**100 events → 115 signals → 5 incidents**, which is the fastest way to see every stage of the
system do real work.

---

## 3. Step by step

### Step 1 — Open the app and sign in

**https://tenex-soc.vercel.app** — the frontend is on Vercel, so there is no free-tier
spin-down and no cold start to sit through before the login page renders.

```
email:    demo@tenex.local
password: tenex-demo-password
```

Sign-in is rate limited to **5 attempts per minute** per client, and a wrong password and an
unknown email return the identical `401 invalid_credentials` on purpose — the API never discloses
whether an account exists.

There is also a **Sign up** link. It works, and on this deployment
`email_verification_enabled` is `true`, so a real confirmation email goes out through Supabase and
you must click the link before you can log in. It buys you nothing here — every account joins the
same single live tenant and sees the same data — so the demo account above is the intended path.

### Step 2 — Get a log to upload, from `backend/data/demo5_tiny/`

**Use these five files and only these five.** They are attached to the email, and they live in the
repo at [`backend/data/demo5_tiny/`](backend/data/demo5_tiny/) — nothing else in `backend/data/`
is sized for the hosted deployment. Each is a real-format ZScaler NSS log carrying all 181
documented fields, and each ships beside a `.labels.json` holding ground truth — the exact
malicious line numbers, the ATT&CK technique, and the victim.

| File — all in `backend/data/demo5_tiny/` | Lines | Malicious | Technique | Primary entity |
|---|--:|--:|---|---|
| **`scenario_c2_beaconing.log`** | 101 | 55 | **T1071.001** — C2 over web protocols | `nbertrando@corp.example` |
| `scenario_data_exfiltration.log` | 73 | 27 | T1567.002 — exfil to cloud storage | `nbertrando@corp.example` |
| `scenario_multi_domain_c2_failover.log` | 181 | 120 | T1008 — fallback channels | `nbertrando@corp.example` |
| `scenario_web_shell_probing.log` | 151 | 90 | T1505.003 — web shell probing | `jnelan@corp.example` |
| `scenario_prompt_injection_canary.log` | 85 | 24 | — (prompt-injection payloads) | `jnelan@corp.example` |

**Start with `backend/data/demo5_tiny/scenario_c2_beaconing.log`.** It is `nbertrando@corp.example`
calling `bfuxjndgrpcpsfbeqb.xyz` from `77.120.238.66` every 60 seconds with 12% jitter for two
hours — a textbook DGA domain and a textbook beacon, blended into benign traffic from five other
users. The labels record the measured shape of it (`cv=0.123`, `mad_jitter=0.096`), so the
beaconing detector's output has something exact to be checked against.

`scenario_prompt_injection_canary.log` is the interesting one to run second: its 24 malicious
requests carry payloads engineered to hijack the LLM — instruction override, delimiter escape,
turn forgery, tool coercion, system-prompt leak — in the `useragent`, `url` and `referer` fields.
Log content is treated as untrusted data end to end, so the triage verdict should come back
unmoved.

### Step 3 — Upload it

The upload control is on the **Analyses** page, top right — the app's landing page after login.
**Click the "Click to browse" control** and select the file from `backend/data/demo5_tiny/` (or
wherever you saved the attachments) in the picker that opens. Use the button; dragging a file onto
the dashed area does not start an upload.

Uploads are limited to **10 per hour** per client. All five demo logs are between 100 KB and
270 KB, so they upload instantly.

### Step 4 — Watch it run

The analysis page streams progress as the upload moves through the pipeline: parse → enrich →
detect → correlate → triage → anonymize.

**Everything up to triage finishes in well under a minute.** Triage is making live LLM calls at
roughly **3 minutes per incident**, so the recommended log takes around 10–15 minutes end to end.
`MAX_TRIAGE_INCIDENTS` is a **cap, not a target** — the run triages whichever is smaller, 15 or
the incident count the upload actually produced, so on this log the cap never binds.

You do not have to wait for triage. Events, signals, evidence and the entity graph are all
populated and browsable as soon as detect and correlate are done.

### Step 5 — Read the result

Worth opening, in roughly this order:

- **The analysis overview** — the funnel: how many events survived each stage, and why the LLM
  only ever sees a few dozen correlated events per incident rather than the raw log.
- **Evidence** — the calculated facts. Machines calculate, the LLM interprets; this tab is the
  first half of that sentence, with percentile annotations against a six-month baseline of what is
  normal for that user, department and org.
- **Incidents** — ranked by fused, calibrated score. The LLM does not set priority; rank comes
  from the fusion score, and the agent contributes disposition, narrative and technique mapping
  only.
- **An incident's detail page** — Narrative, Timeline, Evidence, Signals, Entity graph,
  Investigation guidance, **Agent trace** (every tool call the agent made), and **Feedback**.
  Every claim in the narrative cites event IDs, and those citations are verified programmatically —
  an unverifiable claim gets flagged rather than silently rendered.
- **Tier 2** — the cross-tenant layer: indicator overlap, technique prevalence and first-seen
  propagation, computed over pseudonymized data in a physically separate database.

### Step 6 — Check it against ground truth

`backend/data/demo5_tiny/scenario_c2_beaconing.labels.json` — every log in that directory has a
`.labels.json` beside it — marks **55 of the 101 lines** as the T1071.001 beacon, names
`nbertrando@corp.example` as the victim, and lists the detectors that should fire
(`signal.beaconing`, `signal.rarity`, `signal.dga`) and the disposition the agent should reach
(`true_positive`). Compare that against what the system actually found.

Read the demo as a demo: 55 of 101 lines malicious is a deliberately generous ratio.
[`backend/evals/results.md`](backend/evals/results.md) scores the system at realistic ratios,
where recall drops sharply. Those are the honest numbers.

---

## 4. Where everything lives

| | URL | Credentials |
|---|---|---|
| **Web UI** | https://tenex-soc.vercel.app | `demo@tenex.local` / `tenex-demo-password` |
| API health | https://34-150-170-252.sslip.io/api/health | — |
| API docs (OpenAPI) | https://34-150-170-252.sslip.io/api/docs | — |

RabbitMQ's management console, MinIO's console and Postgres are **not** published. They run on the
VM's internal Docker network only — the local stack exposes them for convenience, production does
not.

`34-150-170-252.sslip.io` resolves to `34.150.170.252`; sslip.io reflects any IP embedded in the
hostname, which gives Caddy a real DNS name to complete an ACME challenge against. The certificate
is a genuine Let's Encrypt one, not self-signed.

### The topology behind those two URLs

| Component | Host |
|---|---|
| `web` (Next.js) | Vercel |
| `api` + nine pipeline workers | One GCE `e2-standard-2` in `us-east4-b`, behind Caddy |
| Postgres + pgvector | Supabase |
| RabbitMQ, Redis, MinIO, Tier 2 Postgres | On the VM |

**Vercel cannot run this backend** — the pipeline is a long-running, queue-driven, multi-stage
process, and serverless functions have no persistent filesystem and time out long before a
multi-minute analysis finishes. So the frontend goes to Vercel and everything else to one VM
running the *same* [`docker-compose.yml`](docker-compose.yml) topology as a local checkout: same
queues, same stage contracts, not a reduced variant. [`deploy/README.md`](deploy/README.md) has
the full rationale, including why not Render and why not managed-everything.

---

## 5. How this differs from running it locally

| | Local | Live |
|---|---|---|
| Setup | Docker, five `make` targets, ~5 min | Open a URL |
| API key | Yours, in `.env` | The deployment's |
| Triage cap | `MAX_TRIAGE_INCIDENTS=10` | 15 |
| Baselines and L3 models | You run `make gen-data` / `make seed` / `make train` | Already provisioned |
| Tenancy | Your own instance | One shared tenant — everyone sees everything |
| Max upload | 200 MB — same proxy path, no platform body cap in front of it | Small files only, see below |
| Consoles (RabbitMQ, MinIO, Postgres) | Exposed on localhost | Not published |

---

## 6. Troubleshooting

**Sign-in appears to work but bounces back to `/login`**
Cookies are blocked for the site. The session cookie is httpOnly and the frontend proxies
`/api/*` through its own origin precisely so the browser files it first-party — but a browser set
to block cookies outright still drops it. Allow cookies for `tenex-soc.vercel.app` and retry.

**`Invalid email or password`**
Check for a trailing space on the paste. After five failed attempts in a minute the endpoint rate
limits — wait sixty seconds rather than retrying immediately, since further attempts are rejected
without ever being checked.

**A multi-megabyte log fails to upload, or errors before any progress appears**
Expected, and it is a property of the hosted frontend rather than the API. Browser uploads go
through Vercel's `/api/*` rewrite (that is what keeps the session cookie first-party), and Vercel
caps a proxied request body far below the API's own 200 MB ceiling — its documented platform
limit is 4.5 MB. The five logs in `backend/data/demo5_tiny/` are all under 270 KB and unaffected;
`backend/data/samples/01-mixed-week.log` is
12.6 MB and will not go through. Posting it straight at the API origin instead does not work
either — that cookie is scoped to the Vercel domain, so the request arrives unauthenticated.
Upload one of the five `backend/data/demo5_tiny/` logs instead. The trade-off is recorded in
[`frontend/next.config.ts`](frontend/next.config.ts).

**Dragging a file onto the upload area does nothing**
Drag-and-drop is not wired up. Click the **Click to browse** control instead and choose the file
from the picker.

**`Too many requests` on upload**
Ten uploads per hour, per client. Wait, or reuse an analysis someone has already run.

**The analysis sits on triage for minutes**
That is expected, not a hang — roughly 3 minutes of live LLM calls per incident, and it is the
one stage that is genuinely slow. Everything else is already browsable while you wait.

**An analysis is marked `failed` with "credit balance is too low"**
The deployment's Anthropic account ran out mid-run. The stage treats HTTP 400 as non-retryable,
correctly, since retrying cannot conjure credit. Incidents triaged before that point keep their
verdicts and stay browsable. Nothing you can do from the UI — flag it to whoever owns the
deployment.

**"Could not load analyses — the API is unreachable"**
The VM is restarting or being redeployed. Check
https://34-150-170-252.sslip.io/api/health — you want `{"status":"ok", ...}` — and reload once it
answers.

**Incidents appear that you did not upload**
One shared tenant, by design. See [Section 1](#1-what-you-need-before-you-start).

**A certificate warning on the API host**
You should not get one; `sslip.io` exists here specifically so the API can hold a real Let's
Encrypt certificate. If you do see a warning, check you are on
`34-150-170-252.sslip.io` and not a lookalike.

**Everything looks right but percentiles read `insufficient history (n=0)`**
The baseline rows for those principals are missing — a deployment-side problem, not a browser one.
Worth reporting; the fix is on the VM, not in the UI.

---

## 7. What to read next

- [`README.md`](README.md) — what the system is and how it is built
- [`AI_APPROACH.md`](AI_APPROACH.md) — the models, what each was benchmarked against, and the
  three results that came back differently than predicted
- [`backend/evals/results.md`](backend/evals/results.md) — every benchmark number
- [`LOCAL_SETUP.md`](LOCAL_SETUP.md) — running the whole stack yourself, on the same five
  `backend/data/demo5_tiny/` logs
- [`deploy/README.md`](deploy/README.md) — how this deployment is provisioned, shipped and secured
- [`docs/`](docs/) — the design docs, written before the code
