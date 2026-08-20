"""Memory module (ladder 3, NOT implemented in this delivery).

Kept as a structural placeholder per requirement book §3/§9. The module stays
disabled in config/modules.json until ladder 3.

Ladder-3 scope:
- plain `.md`/`.json` content files under modules/memory/data/
- summarize + retrieve + daily details; lightweight text search (no vector/semantic)
- memory is CONTENT data, never template-rendered (D9/D10)
"""
FEATURE = {
    "name": "memory",
    "version": "0.0",
    "desc": "Memory: summarize/retrieve/daily details (ladder 3, placeholder)",
    "tools": [],
    "hooks": {},
    "data_dir": True,
}
