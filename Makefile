.PHONY: validate syntax-check lint typecheck test live-skip-check \
        endpoint-registry-check profile-registration-check get-only-check \
        tools-write-check security-scan fixture-safety-check query-param-check \
        git-report

PYTHON := .venv/bin/python
REPORT := .validate/report.xml

validate: syntax-check lint typecheck test live-skip-check \
          endpoint-registry-check profile-registration-check get-only-check \
          tools-write-check security-scan fixture-safety-check query-param-check \
          git-report
	@echo "--------------------------------------------------------"
	@echo "VALIDATE: PASSED (13/13 stages)"

syntax-check:
	@echo "[ 1/13] Syntax/import validation ............."
	@$(PYTHON) -m compileall -q src scripts tests
	@$(PYTHON) -c "import pfsense_mcp"
	@echo "  OK"

lint:
	@echo "[ 2/13] Formatting & linting (ruff) .........."
	@$(PYTHON) -m ruff format --check .
	@$(PYTHON) -m ruff check .
	@echo "  OK"

typecheck:
	@echo "[ 3/13] Static type checking (mypy) ..........."
	@$(PYTHON) -m mypy src/pfsense_mcp scripts
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
