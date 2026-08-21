# claw_se

**claw_se (Small + Security edition)** — a single-file, security-first personal AI assistant. The name is a pun: **S**mall (single file, minimal footprint) and **S**ecurity (every action passes a security kernel).

[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/BYXY01/test_agent_1) [![status](https://img.shields.io/badge/status-experimental-orange)](https://github.com/BYXY01/test_agent_1) [![version](https://img.shields.io/badge/version-0.0.102--%CE%B1-blue)](https://github.com/BYXY01/test_agent_1) [![license](https://img.shields.io/badge/license-planned-lightgrey)](https://github.com/BYXY01/test_agent_1)

---

## Common origin

The Claw series shares one origin. In early 2026 [OpenClaw](https://github.com/openclaw/openclaw) went viral while we were starting to learn the [LangChain](https://github.com/langchain-ai/langchain) framework; a series of experiments followed. In one of them we plugged the **terminal in as a `@tool`** for an Agent — with a surprising result: the program started to modify and iterate on itself, growing file, process, and self-awareness capabilities within just 2 days, getting closer and closer to an AI-cli tool. That inspired two directions:

- **claw_se** — the fixed-security edition: pursues determinism and safety, out of the box.
- **[Claw_EE](https://github.com/BYXY01/Claw_EE.py)** — the seed edition: a few dozen lines whose code reads / rewrites / restarts itself and can grow arbitrary features.

The very first prototype was only **37 lines** (30 after blank lines): swapping the class-sample tool for a `command` executor. The author told the running program "read your own code, how would you add multi-round chat?" — it produced a new version and multi-round chat worked perfectly. "The homework iterated itself."

---

## Introduction

This is **0.0.102-α**. SE = Small + Security (also Simple / Smart / Shield).

Highlights:

- **Single-file distribution** — `builder.py` merges `src_dev/` into one `claw_se.py`; first run self-releases `modules/`, `config/`, `prompt_library/` and auto-installs core dependencies. Windows ships as `claw_se.exe` (PyInstaller onefile) only: a bare `python claw_se.py` on Windows refuses to start.
- **Security kernel (dual switch + three lists)** — a static firewall (blacklist / self-learned, 0 tokens) plus an LLM safety judge that self-learns ("recognize once, immune forever"). The whitelist only skips the LLM, never the static checks. Self-reference defense write-protects the script/module directories.
- **Multi-channel MsgIO bus** — blocking channels (terminal, IM long connections) are thread-bridged, so several channels coexist without freezing the loop; security prompts route back to the channel the request came from.
- **Modular agent (LangChain/LangGraph + checkpointing + auto-summarization)** — modules: `exec` (foreground + background processes), `file` (stateless ops + rollback), `info`, `delegate` (least-privilege submodel delegation), `memory` (opt-in).
- **Input-layer injection guard** — every `receive()` passes `input_guard`; injection is blocked and echoed back before it reaches the loop.

> ⚠️ **Experimental version** — this is currently an experimental version of the project.

---

## Usage

```bash
# Build the single file (products go to dist/)
python3 builder.py --out dist
python3 builder.py --exe --out dist   # Windows: produces claw_se.exe

# Run (first run self-releases modules/config/prompts + auto-installs deps)
python dist/claw_se.py

# Test (offline, no API keys required)
python3 -m pytest tests/unit_tests -q
python3 -m pyflakes src_dev tests builder.py
```

Configuration: `config/providers.json` (copy from `src_dev/config/providers.example.json`), `.env` (API keys via `key_ref` pointers, never committed), `config/modules.json` / `config/security.json` (module enablement and security switches, auto-generated from code defaults on first run).

---

## Timeline

- **2026-03-05** — started learning LangChain (earliest experiment files).
- **2026-03-11** — plugged the terminal in as a `@tool` (37-line prototype `agent_with_tools_cmd.py`); that same night the program read its own code and self-iterated into the multi-round `agent_with_tools_cmd_multiround.py` — "the homework iterated itself".
- **2026-03-11 → 03-13** — within 2 days it grew file/process/self-awareness capabilities, approaching an AI-cli tool; inspired the SE/EE split (MiniClaw → Security Claw → claw_se.py).
- **Ladders 0-4** — skeleton / security kernel / base modules / delegation + memory / single-file distribution.
- **0.0.100** — single-file versioning, stateless `file` tool, psutil process-tree kill.
- **0.0.101** — msgio multi-channel, deterministic process-tree kill, Windows-must-run-exe guard, GitHub CI + auto-release.
- **0.0.102** — install-style plugin loader (manifest + facade + graded checks), requirements.txt as the single dependency source, experimental unix binary flag, Gitee automation.
- **Roadmap** — multi-channel (done) → plugin loader (done) → real channels + provider failover → [OpenClaw](https://github.com/openclaw/openclaw) bridge → in-session memory.

---

## License

Planned; watch the repository.

---

## Acknowledgments

- **[OpenClaw](https://github.com/openclaw/openclaw)** — inspiration.
- **[LangChain](https://github.com/langchain-ai/langchain)** — the framework foundation (Tool/AgentExecutor, LangGraph).
- The class sample code — where it all began.
