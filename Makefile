.PHONY: validate quick syntax-check lint typecheck test live-skip-check \
        endpoint-registry-check profile-registration-check get-only-check \
        tools-write-check security-scan fixture-safety-check query-param-check \
        write-infrastructure-check write-allow-list-check write-capability-check \
        git-report _ruff-format _ruff-check _mypy \
        capture-fixture audit-fixture approve-fixture \
        scaffold-capability checkpoint

PYTHON := .venv/bin/python
REPORT := .validate/report.xml

validate: syntax-check lint typecheck test live-skip-check \
          endpoint-registry-check profile-registration-check get-only-check \
          tools-write-check security-scan fixture-safety-check query-param-check \
          write-infrastructure-check write-allow-list-check write-capability-check \
          git-report
	@echo "--------------------------------------------------------"
	@echo "VALIDATE: PASSED (16/16 stages)"

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
	@echo "[ 1/16] Syntax/import validation ............."
	@$(PYTHON) -m compileall -q src scripts tests
	@$(PYTHON) -c "import pfsense_mcp"
	@echo "  OK"

lint:
	@echo "[ 2/16] Formatting & linting (ruff) .........."
	@$(MAKE) --no-print-directory _ruff-format
	@$(MAKE) --no-print-directory _ruff-check
	@echo "  OK"

typecheck:
	@echo "[ 3/16] Static type checking (mypy) ..........."
	@$(MAKE) --no-print-directory _mypy
	@echo "  OK"

test:
	@echo "[ 4/16] Full pytest suite ......................"
	@mkdir -p .validate
	@$(PYTHON) -m pytest -q --junit-xml=$(REPORT)
	@echo "  OK"

live-skip-check: test
	@echo "[ 5/16] Live-test skip confirmation ............"
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage live-skip
	@echo "  OK"

endpoint-registry-check: test
	@echo "[ 6/16] Endpoint-registry verification ........."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage endpoint-registry
	@echo "  OK"

profile-registration-check: test
	@echo "[ 7/16] Auditor-profile registration ..........."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage profile-registration
	@echo "  OK"

get-only-check: test
	@echo "[ 8/16] GET-only enforcement ...................."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage get-only
	@$(PYTHON) scripts/get_only_check.py
	@echo "  OK"

tools-write-check:
	@echo "[ 9/16] tools/write/ import absence ............"
	@$(PYTHON) scripts/tools_write_check.py
	@echo "  OK"

security-scan:
	@echo "[10/16] Secret / identifying-data scan ........."
	@$(PYTHON) scripts/security_scan.py
	@echo "  OK"

fixture-safety-check:
	@echo "[11/16] Fixture safety validation ..............."
	@$(PYTHON) scripts/fixture_safety.py
	@echo "  OK"

query-param-check: test
	@echo "[12/16] Query-parameter safety validation ......."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage query-param
	@$(PYTHON) scripts/bounded_params_check.py
	@echo "  OK"

write-infrastructure-check: test
	@echo "[13/16] Write-infrastructure test verification ."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage write-infrastructure
	@echo "  OK"

write-allow-list-check:
	@echo "[14/16] Write allow-list emptiness .............."
	@$(PYTHON) scripts/write_allow_list_check.py
	@echo "  OK"

write-capability-check:
	@echo "[15/16] Write-capability inactivity ............."
	@$(PYTHON) scripts/write_capability_check.py
	@echo "  OK"

git-report:
	@echo "[16/16] Git working-tree report (read-only) ....."
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
	@echo "[1/9] Ruff formatting check ..................................."
	@$(MAKE) --no-print-directory _ruff-format
	@echo "  OK"
	@echo "[2/9] Ruff lint check ........................................."
	@$(MAKE) --no-print-directory _ruff-check
	@echo "  OK"
	@echo "[3/9] Incremental mypy ........................................"
	@$(MAKE) --no-print-directory _mypy
	@echo "  OK"
	@echo "[4/9] Complete default pytest suite ..........................."
	@$(PYTHON) -m pytest -q
	@echo "  OK"
	@echo "[5/9] GET-only static enforcement ............................."
	@$(PYTHON) scripts/get_only_check.py
	@echo "  OK"
	@echo "[6/9] tools/write/ import absence ............................."
	@$(PYTHON) scripts/tools_write_check.py
	@echo "  OK"
	@echo "[7/9] Full repository security scan .........................."
	@$(PYTHON) scripts/security_scan.py
	@echo "  OK"
	@echo "[8/9] Write allow-list emptiness .............................."
	@$(PYTHON) scripts/write_allow_list_check.py
	@echo "  OK"
	@echo "[9/9] Write-capability inactivity ............................."
	@$(PYTHON) scripts/write_capability_check.py
	@echo "  OK"
	@echo "--------------------------------------------------------"
	@echo "QUICK: PASSED (9/9 stages)"

# Fixture-capture workflow. Deliberately outside quick/validate — an
# occasional, human-supervised workflow, not a CI gate.
#
# capture-fixture: writes a sanitized PROPOSAL under .fixture_proposals/
#   (never directly into tests/fixtures/). Requires the endpoint to be
#   both verified=True AND have an explicit entry in CAPTURE_POLICIES.
#   Usage: make capture-fixture ENDPOINT=FIREWALL_STATES PARAMS="--param limit=5"
#
# audit-fixture: dry-run only. Independently re-verifies a proposal
#   against fixture_safety, security_scan, and the sanitizer's own
#   audit logic. Never copies anything.
#   Usage: make audit-fixture PROPOSAL=.fixture_proposals/firewall_states_response.proposed.json
#
# approve-fixture: re-runs the exact same audit; only if every check
#   passes, copies the proposal into tests/fixtures/. Never stages or
#   commits — prints the follow-up staging command for a human to run next.
#   Usage: make approve-fixture PROPOSAL=.fixture_proposals/firewall_states_response.proposed.json
capture-fixture:
	@$(PYTHON) scripts/capture_fixture.py $(ENDPOINT) $(PARAMS)

audit-fixture:
	@$(PYTHON) scripts/audit_fixture.py $(PROPOSAL)

approve-fixture:
	@$(PYTHON) scripts/audit_fixture.py $(PROPOSAL) --approve

# Capability-scaffolding proposal generator. Never modifies src/ or
# tests/ — writes only under .capability_proposals/<name>/. No network
# access, no credentials. Human review + manual apply is mandatory.
#   Usage: make scaffold-capability MANIFEST=capability_manifests/x.json DISCOVERY=.discovery_snapshots/x.json
scaffold-capability:
	@$(PYTHON) scripts/scaffold_capability.py $(MANIFEST) --discovery-snapshot $(DISCOVERY)

# Lightweight checkpoint utility: writes CHECKPOINT.md and
# .checkpoint/state.json summarizing git/test/backlog state, so a new
# Claude session can resume without rereading the full conversation.
# Pure Python, no network access. Never modifies the repository except
# those two output files.
checkpoint:
	@$(PYTHON) scripts/checkpoint.py
