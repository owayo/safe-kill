.PHONY: build release install install-hooks clean test fmt check help

# デフォルトターゲット
.DEFAULT_GOAL := help

# 変数
BINARY_NAME := safe-kill
INSTALL_PATH := /usr/local/bin

## ビルドコマンド

build: ## デバッグビルド
	cargo build

release: ## リリースビルド
	cargo build --release

## インストール

install: release ## リリースビルドを作成して /usr/local/bin にインストール
	cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/

install-hooks: ## Claude Code hook の設定手順を表示
	@echo "Claude Code Integration Setup"
	@echo ""
	@echo "1. Add to .claude/settings.json:"
	@echo '   {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"if echo \"$$TOOL_INPUT\" | grep -qE '"'"'(^|[;&|])\\s*(kill|pkill|killall)\\s'"'"'; then echo '"'"'🚫 Use safe-kill instead: safe-kill <PID> or safe-kill --name <name> (like pkill). Use -s <signal> for signal.'"'"' >&2; exit 2; fi"}]}]}}'
	@echo ""
	@echo "2. Add process management rules to CLAUDE.md (see README.md)"
	@echo ""
	@echo "3. Grant permission: claude /permissions add Bash \"safe-kill*\""

## 開発

test: ## テストを実行
	cargo test

test-e2e: ## E2E テストのみ実行
	cargo test --test e2e_tests

test-integration: ## 統合テストのみ実行
	cargo test --test integration_tests

fmt: ## コードをフォーマット
	cargo fmt

check: ## clippy と check を実行
	cargo clippy -- -D warnings
	cargo check

clean: ## ビルド成果物を削除
	cargo clean

## ヘルプ

help: ## このヘルプを表示
	@echo "safe-kill Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Release:"
	@echo "  Use GitHub Actions > Release > Run workflow"
