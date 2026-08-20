"""Dynamic multi-model delegation (ladder 3, NOT implemented in this delivery).

Kept as a structural placeholder per requirement book §3. The module stays
disabled in config/modules.json until ladder 3.

Ladder-3 scope:
- task_to_submodel(prompt_name, input_data, model_id, full_context_share=True,
                   context_content=None, tools_to_share=None, session_id=None, **model_params)
- runtime context trimming (isolation mode, A7) + least-privilege tool sharing (A8)
- sub-agents must go through factory + secure() (fix #11), recursion depth <= max_depth (fix #5)
"""
FEATURE = {
    "name": "delegate",
    "version": "0.0",
    "desc": "Dynamic multi-model delegation (ladder 3, placeholder)",
    "tools": [],
    "hooks": {},
}
