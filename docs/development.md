# Development

The setup and the standard `make` targets are in the README's [Development](../README.md#development) section. This page covers the test suite.

## Running Part of the Tests

| Command | Runs |
|---------|------|
| `make test` | All tests (library, binary, integration, and E2E) |
| `make test-integration` | Only the integration tests (`tests/integration_tests.rs`) |
| `make test-e2e` | Only the E2E tests (`tests/e2e_tests.rs`) |

To run the tests whose names contain a word, pass it to `cargo test` through mise, for example `mise exec -- cargo test --locked ancestry`.

## Test Coverage

- **Library Unit Tests**: 438 tests covering all modules. Ancestry traversal stop conditions (depth limit, parent-PID cycles, PID 1 termination) are verified against injected process trees, since a real process tree cannot be made to exhibit them.
- **Binary Unit Tests**: 41 tests for CLI output utilities, error sanitization, and version checks
- **Integration Tests**: 80 tests with real process trees. Temporary process names include the test runner PID and a sequence number, so concurrent `cargo test` invocations cannot collide while staying within Linux's 15-byte `comm` limit. Partial-success batches are covered by spawning a same-named descendant and an orphan (re-parented to PID 1), which is the only way to make `--name` match processes that differ in kill permission.
- **E2E Tests**: 108 tests for CLI behavior, including private config permissions under a permissive `umask` and sanitization of control characters embedded in clap usage errors
