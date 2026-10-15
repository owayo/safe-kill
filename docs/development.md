# Development

The setup and the standard `make` targets are in the README's [Development](../README.md#development) section. This page covers the test suite.

## Running Part of the Tests

| Command | Runs |
|---------|------|
| `make test` | All tests (library, binary, integration, and E2E) |
| `make test-integration` | Only the integration tests (`tests/integration_tests.rs`) |
| `make test-e2e` | Only the E2E tests (`tests/e2e_tests.rs`) |

To run the tests whose names contain a word, pass it to `cargo test` through mise, for example `mise exec -- env -u SAFE_KILL_ROOT_PID cargo test --locked ancestry`. The `make` targets unset `SAFE_KILL_ROOT_PID` for you: the library and integration tests read it in-process, so an agent session that exports it would otherwise change the trust root, and a test cannot remove it safely while other tests run in parallel.

## Test Coverage

Counts are for macOS; the library tests include OS-specific ones, so the numbers differ on Linux.

- **Library Unit Tests**: 569 tests covering all modules. Conditions that a real process tree cannot be made to exhibit are verified against injected data: ancestry stop conditions (depth limit, parent-PID cycles, PID 1 termination, missing direct ancestors), trust-root detection (a shell parent, an agent whose shell `exec`ed, a PID 1 or subreaper grandparent, a missing grandparent), the pre-kill chain re-check (an ancestor replaced, a target re-parented or gone between the two passes, the fetch order), and the `--name` processing order (children before parents, PID wraparound, cycles). The macOS port backend is tested through an injectable libproc interface — failed queries whose buffer looks exactly like a listener on the target port are never accepted — and with real descriptors closed or replaced between enumeration and query. The `--port` policy is checked against a real child that inherited a listening socket, signal sending is checked through an injected send function so that no test can reach PID 0 or -1, the escaped character set is compared with the Unicode 17.0 data for every code point, and opening a FIFO as the config file is checked not to block.
- **Binary Unit Tests**: 58 tests for CLI output utilities: output sanitization through the real writers, help text, usage-error rendering, and the exit-code rules for output failures
- **Integration Tests**: 80 tests with real process trees. Temporary process names include the test runner PID and a sequence number, so concurrent `cargo test` invocations cannot collide while staying within Linux's 15-byte `comm` limit. Partial-success batches are covered by spawning a same-named descendant and an orphan (re-parented to PID 1), which is the only way to make `--name` match processes that differ in kill permission. A same-named parent and child (a symlink to `/bin/bash` that starts itself) check that `--name` with SIGKILL or SIGTERM leaves no orphan behind.
- **E2E Tests**: 133 tests for CLI behavior, including a relative `HOME` and invalid `[allowed_ports]` entries being configuration errors, the exit codes of PID targets refused by policy, private config permissions under a permissive `umask`, English help on every entry point, control characters in clap usage errors being escaped rather than deleted, and output failures reproduced with `ulimit -f 0` (an actual kill still exits 0 with a warning; `--list` and dry runs exit 255). The binary always runs with an empty `HOME` and without `SAFE_KILL_ROOT_PID`, so the developer's configuration cannot change the results or turn a test into a real kill.

Tests only signal processes they spawned themselves: `--port` tests use `--dry-run` unless the test owns the listener, termination is checked through the child's exit status rather than by signaling a reaped PID, and fixed PIDs in dry-run tests use the nonexistent `999999999`.
