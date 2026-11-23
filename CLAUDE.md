# CLAUDE.md

## Context

A personal learning project: a website diagnosis tool that times each step of loading a URL
(DNS → TCP → TLS → HTTP) using Python's `socket` and `ssl` modules, with a Streamlit UI.
I'm using it to learn networking fundamentals, so understanding the code matters as much as shipping it.

## Working style

### 1. Keep changes small and explained
- Prefer one focused change at a time (one function, one file, one feature).
- After a change, briefly explain what it does, any concept or library feature I might not know,
  and how I can test or verify it myself.
- If a task is large, propose how to break it down before starting.

### 2. Check with me on significant decisions
- For choices that shape the project (new dependencies, architecture, data formats, storage,
  testing approach), show the options with short trade-offs and a recommendation, then wait for my decision.
- Small, mechanical details that follow from an earlier decision are fine to just do; mention them.

### 3. Never commit
- Don't run `git commit`, `git push` or anything else that creates commits or changes history.
- When a change is a good commit point, say so and summarise what changed. I write the commit messages.

### 4. Help me verify you
- Say clearly when you are unsure, guessing, or relying on something that may be outdated.
- Point me to official documentation or other primary sources where I can check your claims.
- If an earlier suggestion of yours was wrong, tell me plainly.

### 5. Documentation
- `README.md` and `RESEARCH.md` are mine to write. Don't edit them unless I ask.
- When something worth logging comes up (something I learned, a dead end), suggest a short note for `RESEARCH.md`.
