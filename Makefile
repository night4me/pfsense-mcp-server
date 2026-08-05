.PHONY: validate quick syntax-check lint typecheck test live-skip-check \
        endpoint-registry-check profile-registration-check get-only-check \
        tools-write-check security-scan fixture-safety-check query-param-check \
        git-report _ruff-format _ruff-check _mypy

PYTHON := .venv/bin/python
REPORT := .validate/report.xml

validate: syntax-check lint typecheck test live-skip-check \
          endpoint-registry-check profile-registration-check get-only-check \
          tools-write-check security-scan fixture-safety-check query-param-check \
          git-report
	@echo "--------------------------------------------------------"
	@echo "VALIDATE: PASSED (13/13 stages)"

# Internal targets: hold the actual ruff/mypy command logic exactly once.
# Not meant to be invoked directly — lint, typecheck, and quick all call
# these via `$(MAKE) --no-print-directory` so each keeps its own
# stage-appropriate progress label (13-stage vs. 7-stage) without
# duplicating the underlying command.
_ruff-format:
	@$(PYTHON) -m ruff format --check .

_ruff-check:
	@$(PYTHON) -m ruff check .

_mypy:
	@$(PYTHON) -m mypy src/pfsense_mcp scripts

syntax-check:
	@echo "[ 1/13] Syntax/import validation ............."
	@$(PYTHON) -m compileall -q src scripts tests
	@$(PYTHON) -c "import pfsense_mcp"
	@echo "  OK"

lint:
	@echo "[ 2/13] Formatting & linting (ruff) .........."
	@$(MAKE) --no-print-directory _ruff-format
	@$(MAKE) --no-print-directory _ruff-check
	@echo "  OK"

typecheck:
	@echo "[ 3/13] Static type checking (mypy) ..........."
	@$(MAKE) --no-print-directory _mypy
	@echo "  OK"

test:
	@echo "[ 4/13] Full pytest suite ......................"
	@mkdir -p .validate
	@$(PYTHON) -m pytest -q --junit-xml=$(REPORT)
	@echo "  OK"

live-skip-check: test
	@echo "[ 5/13] Live-test skip confirmation ............"
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage live-skip
	@echo "  OK"

endpoint-registry-check: test
	@echo "[ 6/13] Endpoint-registry verification ........."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage endpoint-registry
	@echo "  OK"

profile-registration-check: test
	@echo "[ 7/13] Auditor-profile registration ..........."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage profile-registration
	@echo "  OK"

get-only-check: test
	@echo "[ 8/13] GET-only enforcement ...................."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage get-only
	@$(PYTHON) scripts/get_only_check.py
	@echo "  OK"

tools-write-check:
	@echo "[ 9/13] tools/write/ import absence ............"
	@$(PYTHON) scripts/tools_write_check.py
	@echo "  OK"

security-scan:
	@echo "[10/13] Secret / identifying-data scan ........."
	@$(PYTHON) scripts/security_scan.py
	@echo "  OK"

fixture-safety-check:
	@echo "[11/13] Fixture safety validation ..............."
	@$(PYTHON) scripts/fixture_safety.py
	@echo "  OK"

query-param-check: test
	@echo "[12/13] Query-parameter safety validation ......."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage query-param
	@$(PYTHON) scripts/bounded_params_check.py
	@echo "  OK"

git-report:
	@echo "[13/13] Git working-tree report (read-only) ....."
	@$(PYTHON) scripts/git_report.py

# quick: fast developer-feedback loop. Deliberately NOT the authoritative
# pre-commit gate — validate remains that. quick reuses the same
# ruff/mypy command logic (via the _ruff-format/_ruff-check/_mypy
# internal targets) and the same get_only_check.py/tools_write_check.py/
# security_scan.py scripts as validate, but skips JUnit report
# generation, fixture-safety, bounded-parameter, and git-report checks.
#
# Deferred optimization: selective (changed-file-only) test execution
# was deliberately NOT implemented here. Reconsider only when one or
# more of the following becomes true:
#   - the default test suite consistently exceeds ~10 seconds,
#   - `make validate` consistently exceeds ~15 seconds,
#   - the repository grows enough that full static/security scanning
#     becomes materially expensive.
# Until then, running the complete suite is simpler and more reliable.
quick:
	@echo "[1/7] Ruff formatting check ..................................."
	@$(MAKE) --no-print-directory _ruff-format
	@echo "  OK"
	@echo "[2/7] Ruff lint check ........................................."
	@$(MAKE) --no-print-directory _ruff-check
	@echo "  OK"
	@echo "[3/7] Incremental mypy ........................................"
	@$(MAKE) --no-print-directory _mypy
	@echo "  OK"
	@echo "[4/7] Complete default pytest suite ..........................."
	@$(PYTHON) -m pytest -q
	@echo "  OK"
	@echo "[5/7] GET-only static enforcement ............................."
	@$(PYTHON) scripts/get_only_check.py
	@echo "  OK"
	@echo "[6/7] tools/write/ import absence ............................."
	@$(PYTHON) scripts/tools_write_check.py
	@echo "  OK"
	@echo "[7/7] Full repository security scan .........................."
	@$(PYTHON) scripts/security_scan.py
	@echo "  OK"
	@echo "--------------------------------------------------------"
	@echo "QUICK: PASSED (7/7 stages)"
