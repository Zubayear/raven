# AGENTS.md

## Repo Map
- Zig project with one executable entrypoint: `src/main.zig`.
- `src/root.zig` is the library root used by `build.zig`; it contains the only unit test.
- `build.zig` wires the library into the executable as `raven_lib`.
- `build.zig.zon` sets the minimum Zig version to `0.14.1`.
- Package contents are limited to `build.zig`, `build.zig.zon`, and `src/`; add new tracked source paths there if you want them packaged.

## Commands
- `zig build` installs the library and executable.
- `zig build run -- [args...]` runs the app from the install directory.
- `zig build test` runs both the library test artifact and the executable test artifact.
- There is no repo-defined formatter, linter, or task runner.

## Repo-Specific Gotchas
- `src/main.zig` is a long-lived TCP server bound to `127.0.0.1:5882`; expect `run` to block in an accept loop.
- `build.zig.zon` includes a package fingerprint; do not change it unless you are intentionally changing package identity.
- Build outputs are `.zig-cache/` and `zig-out/`; both are ignored.
