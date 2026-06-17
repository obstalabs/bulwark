# Bulwark — Linux fanotify read gate.
# fanotify requires CAP_SYS_ADMIN; integration tests must run as root.

CARGO ?= cargo

.PHONY: build release test lint fmt fmt-check clean it

build:
	$(CARGO) build

release:
	$(CARGO) build --release

# Unit tests only (no privileges required).
test:
	$(CARGO) test

# Integration tests that exercise the live gate. Require root for fanotify.
# Run on a Linux host: `sudo make it`.
it:
	$(CARGO) test --test gate_integration -- --ignored --test-threads=1

lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

clean:
	$(CARGO) clean
