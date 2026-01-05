.PHONY: build release install install-hooks clean test fmt check help

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME := safe-kill
INSTALL_PATH := /usr/local/bin

## Build Commands

build: ## Build debug version
	cargo build

release: ## Build release version
	cargo build --release

## Installation

install: release ## Build release and install to /usr/local/bin
	cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/

install-hooks: ## Show Claude Code hook setup instructions
	@echo "Claude Code Integration Setup"
	@echo ""
	@echo "1. Add to .claude/settings.json:"
	@echo '   {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"if echo \"$$TOOL_INPUT\" | grep -qE '"'"'(^|[;&|])\\s*(kill|pkill|killall)\\s'"'"'; then echo '"'"'🚫 Use safe-kill instead: safe-kill <PID> or safe-kill -n <name> (like pkill). Use -s <signal> for signal.'"'"' >&2; exit 2; fi"}]}]}}'
	@echo ""
	@echo "2. Add process management rules to CLAUDE.md (see README.md)"
	@echo ""
	@echo "3. Grant permission: claude /permissions add Bash \"safe-kill*\""

## Development

test: ## Run tests
	cargo test

test-e2e: ## Run E2E tests only
	cargo test --test e2e_tests

test-integration: ## Run integration tests only
	cargo test --test integration_tests

fmt: ## Format code
	cargo fmt

check: ## Run clippy and check
	cargo clippy -- -D warnings
	cargo check

clean: ## Clean build artifacts
	cargo clean

## Help

help: ## Show this help message
	@echo "safe-kill Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Release:"
	@echo "  Use GitHub Actions > Release > Run workflow"
