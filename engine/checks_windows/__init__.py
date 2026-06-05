"""Windows check modules.

Each module exports a `run(ctx) -> list[Finding]` function. Same contract as
checks_macos. Modules use `run_ps` for PowerShell queries (preferring JSON
output for clean parsing) and `run_cmd` for legacy executables (reg, sc, etc.).
"""
