# Prompt Injection: Exploiting and Defending AI Applications

A hands-on workshop where you'll break an AI app, watch it defend itself, and then tune the defenses yourself.

No PhD required. If you can open a terminal and run a command, you're good.

---

## What You'll Walk Away With

- A real understanding of what prompt injection actually is (not just a buzzword)
- Experience running live attacks against a working AI guard
- The ability to tune defenses and measure whether they work
- A story to tell at your next security review

---

## What You Need Before You Show Up

| Requirement | Why |
|-------------|-----|
| Python 3.10 or newer | To run the lab server |
| A terminal | Mac/Linux: any terminal. **Windows: use Git Bash** (installed with Git) — the lab commands don't work in PowerShell or Command Prompt |
| `curl` | To fire requests at the server (already included on Mac, Linux and in Git Bash) |
| Git | To clone this repo. Clone it — don't download the ZIP, because Lab 5 uses `git` to reset your changes |

That's it. No cloud accounts, no special hardware, no 47-step setup.

### Do I need Docker or a VM?

No. Run everything directly on your laptop.

- **Is it safe?** Yes. The lab server only accepts connections from your own machine, uses fake data and simulated tools, and never sends anything anywhere.
- **Will it change my system?** No. Everything installs into one project folder (`.venv`). Delete the folder and it's gone. No admin rights needed on Mac or Windows.
- **Work laptop blocks installs or local servers?** Use a personal laptop, or a VM if you already have one. The steps are the same.
- **Using a VM?** Run everything inside it — the server, `curl`, and the lab commands. A server in the VM won't be reachable from your host.
- **No GPU, no API keys, no AI model to download.** The lab app is lightweight.

---

## Setup (Do This Before the Workshop Starts)

### Step 1 — Clone the repo

```bash
git clone https://github.com/mdilyasahmed/prompt-injection-workshop.git
cd prompt-injection-workshop/prompt_injection_tool
```

### Step 2 — Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> **Windows (Git Bash):** use `python` instead of `python3` everywhere in this workshop, and activate with `source .venv/Scripts/activate`
>
> **Ubuntu/Debian:** if `venv` fails, run `sudo apt install python3-venv` first

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Start the server

```bash
python3 -m uvicorn server:app --port 8010
```

You should see:

```
Uvicorn running on http://127.0.0.1:8010
```

### Step 5 — Check it's alive

Leave this terminal running. Open a **second terminal**, go to the same folder, and run:

```bash
cd prompt-injection-workshop/prompt_injection_tool
curl http://localhost:8010/health
```

Use this second terminal for all the lab commands.

Expected response:

```json
{"status": "ok"}
```

If you see that — you're ready. See you in the workshop.

---

## Workshop Labs

| Lab | Topic | Time |
|-----|-------|------|
| Lab 0 | Setup and smoke test | 5 min |
| Lab 1 | Direct prompt injection | 25 min |
| Lab 2 | Indirect injection | 25 min |
| Lab 3 | Tool abuse and RBAC | 30 min |
| Lab 4 | Defense tuning | 35 min |
| Lab 5 | CTF: Beat the Guard | 25 min |

Full step-by-step instructions are in [`lab-guide.md`](lab-guide.md).

---

## Ground Rules

Everything in this workshop runs on your own laptop against a deliberately weak demo server. Only use these techniques on systems you own or are authorized to assess.

---

## Questions?

Raise your hand. Ask in the room. There are no dumb questions — only dumb attacks (and we're going to run those too).
