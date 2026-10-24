# One-command gates. CI runs the same targets.
CARGO ?= cargo
COVERAGE_MIN ?= 80

.PHONY: check fmt fmt-check lint doc test coverage coverage-report demo vectors bench bench-table clean

## check: everything CI gates on (format, lint, docs, tests, coverage threshold)
check: fmt-check lint doc test coverage

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

## lint: clippy on every target with warnings as errors
lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings

## doc: rustdoc with warnings as errors (missing docs, broken links)
doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --locked

test:
	$(CARGO) test --all-targets --locked
	$(CARGO) test --doc --locked

## coverage: line coverage of src/ (lib + CLI) under the full test suite; fails below COVERAGE_MIN
coverage:
	$(CARGO) llvm-cov --all-targets --locked --fail-under-lines $(COVERAGE_MIN) --summary-only

coverage-report:
	$(CARGO) llvm-cov --all-targets --locked --html

## demo: offline end-to-end run against the bundled RFC vectors and seeded simulations
demo:
	./scripts/demo.sh

vectors:
	$(CARGO) run --quiet --release --locked -- vectors

## bench: criterion benchmarks (statistical; slow)
bench:
	$(CARGO) bench --locked

## bench-table: the README benchmark table
bench-table:
	$(CARGO) run --quiet --release --locked -- bench --suite ed25519 --sizes 4,8,16,32,64,128 --iterations 15 --dkg-max-n 64

clean:
	$(CARGO) clean
