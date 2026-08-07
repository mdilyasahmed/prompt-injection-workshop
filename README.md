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
| A terminal | Mac Terminal, iTerm, Windows Terminal — anything works |
| `curl` | To fire requests at the server (comes pre-installed on Mac/Linux) |
| Git | To clone this repo |

That's it. No cloud accounts, no special hardware, no 47-step setup.

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

> Windows users: use `.venv\Scripts\activate` instead

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

Open a **second terminal** and run:

```bash
curl http://localhost:8010/health
```

Expected response:

```json
{"status": "ok"}
```

If you see that — you're ready. See you in the workshop.

---

## Workshop Labs

| Lab | Topic | Time |
|-----|-------|------|
| Lab 0 | Setup and smoke test | 15 min |
| Lab 1 | Direct prompt injection | 45 min |
| Lab 2 | Indirect injection | 45 min |
| Lab 3 | Tool abuse and RBAC | 45 min |
| Lab 4 | Defense tuning | 60 min |

Full step-by-step instructions are in [`lab-guide.md`](lab-guide.md).

---

## Questions?

Raise your hand. Ask in the room. There are no dumb questions — only dumb attacks (and we're going to run those too).
