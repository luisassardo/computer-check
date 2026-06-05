"""macOS check modules.

Each module exports a `run(ctx) -> list[Finding]` function.
Modules are pure: no I/O outside of `run_cmd` and reading documented system paths.
"""
