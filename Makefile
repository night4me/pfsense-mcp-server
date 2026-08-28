.PHONY: validate quick syntax-check lint typecheck test live-skip-check \
        endpoint-registry-check profile-registration-check get-only-check \
        tools-write-check security-scan git-identity-check security-static-check fixture-safety-check query-param-check \
        write-infrastructure-check write-allow-list-check write-capability-check \
        contract-check docs-check git-report _ruff-format _ruff-check _mypy \
        capture-fixture audit-fixture approve-fixture \
        scaffold-capability checkpoint \
        coverage security-static package-check reproducible-build artifact-manifest release-check \
        docs-build docs-serve docs-freshness-check sbom min-deps-check witness-daemon-check guidance-corpus-audit \
        pfrest-privilege-crosscheck

PYTHON := .venv/bin/python
REPORT := .validate/report.xml

# Tests that cannot safely collect under pytest-xdist -- kept out of the
# parallel worker pool and run in a small serial pass instead. See
# AGENTS.md's "Test parallelism" note for why each one is here; do not add
# to this list to work around a flake without root-causing it first.
#   - test_random_ciphertext_...: its @pytest.mark.parametrize list calls
#     os.urandom() at collection time, so each xdist worker subprocess
#     collects different bytes and different parametrize IDs.
#   - test_importing_mcp_entrypoints_never_loads_acceptance_module: asserts
#     a fresh, untouched sys.modules state by design -- inherently a
#     first-import-only test.
XDIST_SERIAL_ONLY := \
	tests/tier1/test_crypto.py::test_random_ciphertext_never_raises_anything_but_artifact_decryption_error \
	tests/tier1/test_acceptance_isolation.py::test_importing_mcp_entrypoints_never_loads_acceptance_module
XDIST_DESELECT := $(foreach t,$(XDIST_SERIAL_ONLY),--deselect $(t))
XDIST_ARGS := -n 6 --dist=loadscope $(XDIST_DESELECT)

validate: syntax-check lint typecheck test live-skip-check \
          endpoint-registry-check profile-registration-check get-only-check \
          tools-write-check security-scan git-identity-check security-static-check fixture-safety-check query-param-check \
          write-infrastructure-check write-allow-list-check write-capability-check \
          contract-check docs-check git-report
	@echo "--------------------------------------------------------"
	@echo "VALIDATE: PASSED (20/20 stages)"

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
	@$(PYTHON) -m mypy src/pfsense_mcp scripts lab witness_daemon signing

syntax-check:
	@echo "[ 1/20] Syntax/import validation ............."
	@$(PYTHON) -m compileall -q src scripts tests lab witness_daemon signing
	@$(PYTHON) -c "import pfsense_mcp"
	@echo "  OK"

lint:
	@echo "[ 2/20] Formatting & linting (ruff) .........."
	@$(MAKE) --no-print-directory _ruff-format
	@$(MAKE) --no-print-directory _ruff-check
	@echo "  OK"

typecheck:
	@echo "[ 3/20] Static type checking (mypy) ..........."
	@$(MAKE) --no-print-directory _mypy
	@echo "  OK"

test:
	@echo "[ 4/20] Full pytest suite (xdist -n 6 + serial isolation pass) ."
	@mkdir -p .validate
	@$(PYTHON) -m pytest -q $(XDIST_ARGS) --junit-xml=.validate/report_parallel.xml
	@$(PYTHON) -m pytest -q $(XDIST_SERIAL_ONLY) --junit-xml=.validate/report_serial.xml
	@$(PYTHON) scripts/merge_junit_reports.py .validate/report_parallel.xml .validate/report_serial.xml --output $(REPORT)
	@echo "  OK"

live-skip-check: test
	@echo "[ 5/20] Live-test skip confirmation ............"
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage live-skip
	@echo "  OK"

endpoint-registry-check: test
	@echo "[ 6/20] Endpoint-registry verification ........."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage endpoint-registry
	@echo "  OK"

profile-registration-check: test
	@echo "[ 7/20] Auditor-profile registration ..........."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage profile-registration
	@echo "  OK"

get-only-check: test
	@echo "[ 8/20] GET-only enforcement ...................."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage get-only
	@$(PYTHON) scripts/get_only_check.py
	@echo "  OK"

tools-write-check:
	@echo "[ 9/20] tools/write/ import scope ............."
	@$(PYTHON) scripts/tools_write_check.py
	@echo "  OK"

security-scan:
	@echo "[10/20] Secret / identifying-data scan ........."
	@$(PYTHON) scripts/security_scan.py
	@echo "  OK"

git-identity-check:
	@echo "[11/20] Git identity leak check .................."
	@$(PYTHON) scripts/git_identity_check.py
	@echo "  OK"

security-static-check:
	@echo "[12/20] Static security analysis (bandit) ......"
	@$(MAKE) --no-print-directory security-static
	@echo "  OK"

fixture-safety-check:
	@echo "[13/20] Fixture safety validation ..............."
	@$(PYTHON) scripts/fixture_safety.py
	@echo "  OK"

query-param-check: test
	@echo "[14/20] Query-parameter safety validation ......."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage query-param
	@$(PYTHON) scripts/bounded_params_check.py
	@echo "  OK"

write-infrastructure-check: test
	@echo "[15/20] Write-infrastructure test verification ."
	@$(PYTHON) scripts/validate_junit.py $(REPORT) --stage write-infrastructure
	@echo "  OK"

write-allow-list-check:
	@echo "[16/20] Write allow-list scope .................."
	@$(PYTHON) scripts/write_allow_list_check.py
	@echo "  OK"

write-capability-check:
	@echo "[17/20] Write-capability inactivity ............."
	@$(PYTHON) scripts/write_capability_check.py
	@echo "  OK"

contract-check:
	@echo "[18/20] Public MCP contract snapshot ............"
	@$(PYTHON) scripts/public_contract.py
	@echo "  OK"

docs-check:
	@echo "[19/20] Documentation consistency ..............."
	@$(PYTHON) scripts/validate_docs.py
	@echo "  OK"

git-report:
	@echo "[20/20] Git working-tree report (read-only) ....."
	@$(PYTHON) scripts/git_report.py

# quick: fast developer-feedback loop. Deliberately NOT the authoritative
# pre-commit gate — validate remains that. quick reuses the same
# ruff/mypy command logic (via the _ruff-format/_ruff-check/_mypy
# internal targets) and the same get_only_check.py/tools_write_check.py/
# security_scan.py/git_identity_check.py scripts as validate, but skips
# JUnit report generation, fixture-safety, bounded-parameter, and
# git-report checks.
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
	@echo "[1/11] Ruff formatting check .................................."
	@$(MAKE) --no-print-directory _ruff-format
	@echo "  OK"
	@echo "[2/11] Ruff lint check ........................................"
	@$(MAKE) --no-print-directory _ruff-check
	@echo "  OK"
	@echo "[3/11] Incremental mypy ......................................."
	@$(MAKE) --no-print-directory _mypy
	@echo "  OK"
	@echo "[4/11] Complete default pytest suite (xdist -n 6 + serial) ....."
	@$(PYTHON) -m pytest -q $(XDIST_ARGS)
	@$(PYTHON) -m pytest -q $(XDIST_SERIAL_ONLY)
	@echo "  OK"
	@echo "[5/11] GET-only static enforcement ............................"
	@$(PYTHON) scripts/get_only_check.py
	@echo "  OK"
	@echo "[6/11] tools/write/ import scope ............................."
	@$(PYTHON) scripts/tools_write_check.py
	@echo "  OK"
	@echo "[7/11] Full repository security scan .........................."
	@$(PYTHON) scripts/security_scan.py
	@echo "  OK"
	@echo "[8/11] Git identity leak check ................................."
	@$(PYTHON) scripts/git_identity_check.py
	@echo "  OK"
	@echo "[9/11] Static security analysis (bandit) ......................"
	@$(MAKE) --no-print-directory security-static
	@echo "  OK"
	@echo "[10/11] Write allow-list scope .................................."
	@$(PYTHON) scripts/write_allow_list_check.py
	@echo "  OK"
	@echo "[11/11] Write-capability inactivity ............................"
	@$(PYTHON) scripts/write_capability_check.py
	@echo "  OK"
	@echo "--------------------------------------------------------"
	@echo "QUICK: PASSED (11/11 stages)"

coverage:
	@$(PYTHON) -m pytest --cov=pfsense_mcp --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml

security-static:
	@$(PYTHON) -m bandit -c pyproject.toml -r src/pfsense_mcp scripts witness_daemon signing

package-check:
	@$(PYTHON) -m build --no-isolation --sdist --wheel
	@$(PYTHON) scripts/verify_distribution.py dist
	@tmp_dir=$$(mktemp -d); \
	  trap 'rm -rf "$$tmp_dir"' EXIT; \
	  if $(PYTHON) -m venv "$$tmp_dir/venv" >/dev/null 2>&1; then \
	    "$$tmp_dir/venv/bin/python" -m pip install --quiet dist/*.whl; \
	  elif command -v uv >/dev/null; then \
	    uv venv --quiet --python $(PYTHON) --clear "$$tmp_dir/venv"; \
	    uv pip install --quiet --python "$$tmp_dir/venv/bin/python" dist/*.whl; \
	  else \
	    echo "package-check: clean environment creation requires ensurepip or uv" >&2; exit 1; \
	  fi; \
	  "$$tmp_dir/venv/bin/python" -c "import pfsense_mcp.server"; \
	  if "$$tmp_dir/venv/bin/pfsense-mcp-server" >"$$tmp_dir/stdout" 2>"$$tmp_dir/stderr"; then exit 1; fi; \
	  grep -q "configuration error" "$$tmp_dir/stderr"; \
	  ! grep -q "Traceback" "$$tmp_dir/stderr"

reproducible-build:
	@$(PYTHON) scripts/reproducible_build.py

# Network-dependent (resolves and installs real package versions from
# PyPI) and slower than quick/validate -- same scoping rationale as
# reproducible-build above, not a quick/validate stage.
min-deps-check:
	@$(PYTHON) scripts/verify_min_dependencies.py

artifact-manifest:
	@$(PYTHON) scripts/artifact_manifest.py dist

release-check:
	@$(PYTHON) scripts/release_state_check.py
	@$(MAKE) --no-print-directory validate
	@$(MAKE) --no-print-directory package-check
	@$(PYTHON) -m twine check --strict dist/*
	@$(MAKE) --no-print-directory reproducible-build
	@$(MAKE) --no-print-directory min-deps-check
	@$(MAKE) --no-print-directory artifact-manifest
	@echo "RELEASE-CHECK: PASSED (offline; no tag, upload, credentials, or network appliance access)"

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

# Documentation site (mkdocs, requires the optional `docs` extra:
# pip install -e ".[docs]"). docs-build is the CI-equivalent check --
# --strict turns any broken internal link or nav reference into a
# build failure, catching exactly the class of regression a raw
# heading/file rename can silently introduce. Builds to site/
# (git-ignored, like dist/) -- never committed. This does not deploy
# anything: GitHub Pages is live (https://night4me.github.io/pfsense-mcp-server/)
# but redeploying it after a docs change is `mkdocs gh-deploy`, run
# manually -- see docs-freshness-check below for the drift this can
# leave undetected, and mkdocs.yml's own comment for the deploy
# procedure. Enabling *automatic* deployment on every push remains a
# separate, explicit owner decision, not something building the site
# locally implies.
docs-build:
	@$(PYTHON) -m mkdocs build --strict

docs-serve:
	@$(PYTHON) -m mkdocs serve

# Detects (never fixes) drift between the live gh-pages deployment and
# current docs/mkdocs.yml -- see scripts/docs_pages_freshness_check.py's
# own docstring for the full mechanism. Requires network access (a
# read-only fetch of the gh-pages ref), unlike release-check.
docs-freshness-check:
	@$(PYTHON) scripts/docs_pages_freshness_check.py

# Maintainer-invoked audit (task Phase 18): verify every guidance registry
# entry's pinned excerpt is still present, verbatim, on its live
# canonical_url. Requires network access; not part of validate/quick/
# release-check for that reason (same rationale as any live-network
# check in this project). Exits non-zero on drift/fetch failure -- a
# documentation site change should be a visible maintenance finding, not
# silent wrong guidance.
guidance-corpus-audit:
	@$(PYTHON) scripts/guidance_corpus_audit.py

# Advisory READ-only cross-check (pfREST_LIVE_GUIDANCE_ARC, 2026-08-28):
# does PFREST_UPSTREAM's declared "Allowed privileges" for each tool's
# mapped endpoint agree with LIVE_APPLIANCE_SCHEMA's (if a real appliance
# is configured via the standard PFSENSE_* runtime environment variables)
# and with this project's own ADR-033 pinned-source algorithm? Requires
# network access (a live fetch of the public pfREST OpenAPI document, and
# optionally one authenticated GET against a configured appliance); not
# part of validate/quick/release-check for that reason (same rationale as
# guidance-corpus-audit above). Never grants a privilege, modifies a
# service account, or changes ADR-033's own mapping -- exits non-zero only
# on a genuine cross-source DRIFT finding.
pfrest-privilege-crosscheck:
	@$(PYTHON) scripts/pfrest_privilege_crosscheck.py

# Software Bill of Materials (SBOM) generation. Deliberately outside
# quick/validate/release-check -- an occasional, explicit, network-
# requiring workflow (installs a pinned third-party tool from PyPI into a
# throwaway venv), not a CI gate, matching
# docs/DEPENDENCY_POLICY.md's "SBOM tooling is not a runtime dependency."
#
# Builds a fresh wheel, installs it into one clean, isolated venv (same
# pattern as package-check -- never the developer host, per
# DEPENDENCY_POLICY.md's "should describe the built distribution
# environment, not the developer host"), generates a CycloneDX JSON SBOM
# from that venv using a second, separate throwaway venv holding only the
# pinned generator tool (kept apart so the tool's own dependencies never
# appear in the target SBOM), then verifies the result offline via
# verify_sbom.py before printing its location.
#
# Output is a local artifact only (dist/sbom/, git-ignored, same as
# dist/): attaching it to an actual GitHub Release remains a separate,
# explicit owner action after manual review, per DEPENDENCY_POLICY.md --
# this target does not touch Git, tags, or any release/publish workflow.
CYCLONEDX_BOM_VERSION := 7.3.1
SBOM_OUTPUT := dist/sbom/pfsense-mcp-server-sbom.json

sbom:
	@command -v uv >/dev/null || { echo "sbom: requires uv (https://docs.astral.sh/uv/) to install a pinned generator tool" >&2; exit 1; }
	@$(PYTHON) -m build --no-isolation --sdist --wheel
	@mkdir -p dist/sbom
	@tmp_dir=$$(mktemp -d); \
	  trap 'rm -rf "$$tmp_dir"' EXIT; \
	  uv venv --quiet --python $(PYTHON) --clear "$$tmp_dir/target-venv"; \
	  uv pip install --quiet --python "$$tmp_dir/target-venv/bin/python" dist/*.whl; \
	  uv venv --quiet --python $(PYTHON) --clear "$$tmp_dir/tool-venv"; \
	  uv pip install --quiet --python "$$tmp_dir/tool-venv/bin/python" "cyclonedx-bom==$(CYCLONEDX_BOM_VERSION)"; \
	  "$$tmp_dir/tool-venv/bin/cyclonedx-py" environment "$$tmp_dir/target-venv/bin/python" \
	    --pyproject pyproject.toml --mc-type application --sv 1.6 --output-reproducible \
	    -o $(SBOM_OUTPUT)
	@$(PYTHON) scripts/verify_sbom.py $(SBOM_OUTPUT)
	@echo "sbom: generated $(SBOM_OUTPUT) (local artifact only -- not attached to any release)"

# witness_daemon/ is a separate deployable (the Proxmox-host TPM witness
# daemon, docs/tier1/specs/anti_rollback_tpm_host_witness.md) -- never
# shipped in this package, excluded from the default pytest collection
# (pyproject.toml), but its own tests are real and should not silently
# rot: this target runs them explicitly, and CI calls it on every push.
witness-daemon-check:
	@echo "witness-daemon-check: running witness_daemon/'s own offline test suite"
	@$(PYTHON) -m pytest -q witness_daemon/
	@echo "witness-daemon-check: OK"
