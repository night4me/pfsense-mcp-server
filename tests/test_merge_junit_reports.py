"""Unit tests for scripts/merge_junit_reports.py, using synthetic JUnit XML
rather than real pytest runs."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from merge_junit_reports import main, merge


def _write(tmp_path, name: str, testcases_xml: str, *, wrap_testsuites: bool = True):
    inner = f"""<testsuite name="pytest" tests="1">
    {testcases_xml}
  </testsuite>"""
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>\n<testsuites>\n  {inner}\n</testsuites>\n'
        if wrap_testsuites
        else inner
    )
    path = tmp_path / name
    path.write_text(xml)
    return path


def test_merge_combines_testcases_from_both_files(tmp_path):
    a = _write(tmp_path, "a.xml", '<testcase classname="tests.test_a" name="test_one"/>')
    b = _write(tmp_path, "b.xml", '<testcase classname="tests.test_b" name="test_two"/>')
    out = tmp_path / "merged.xml"

    merge([a, b], out)

    root = ET.parse(out).getroot()
    names = sorted(tc.get("name") for tc in root.iter("testcase"))
    assert names == ["test_one", "test_two"]


def test_merge_accepts_a_lone_testsuite_root(tmp_path):
    # pytest emits a bare <testsuite> root (no <testsuites> wrapper) when a
    # run produces exactly one suite -- the serial isolation pass in `make
    # test` is exactly this case.
    a = _write(
        tmp_path,
        "a.xml",
        '<testcase classname="tests.test_a" name="test_one"/>',
        wrap_testsuites=True,
    )
    b_path = tmp_path / "b.xml"
    b_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<testsuite name="pytest" tests="1"><testcase classname="tests.test_b" name="test_two"/></testsuite>\n'
    )
    out = tmp_path / "merged.xml"

    merge([a, b_path], out)

    root = ET.parse(out).getroot()
    names = sorted(tc.get("name") for tc in root.iter("testcase"))
    assert names == ["test_one", "test_two"]


def test_merge_preserves_failure_detail(tmp_path):
    a = _write(
        tmp_path,
        "a.xml",
        '<testcase classname="tests.test_a" name="test_fails"><failure message="boom"/></testcase>',
    )
    out = tmp_path / "merged.xml"

    merge([a], out)

    root = ET.parse(out).getroot()
    (testcase,) = list(root.iter("testcase"))
    assert testcase.find("failure") is not None
    assert testcase.find("failure").get("message") == "boom"


def test_main_errors_cleanly_on_missing_input(tmp_path, capsys):
    missing = tmp_path / "does_not_exist.xml"
    out = tmp_path / "merged.xml"

    import sys as _sys

    old_argv = _sys.argv
    try:
        _sys.argv = ["merge_junit_reports.py", str(missing), "--output", str(out)]
        rc = main()
    finally:
        _sys.argv = old_argv

    assert rc == 1
    assert not out.exists()
    assert "missing input file" in capsys.readouterr().err


def test_main_succeeds_and_writes_output(tmp_path):
    a = _write(tmp_path, "a.xml", '<testcase classname="tests.test_a" name="test_one"/>')
    out = tmp_path / "merged.xml"

    import sys as _sys

    old_argv = _sys.argv
    try:
        _sys.argv = ["merge_junit_reports.py", str(a), "--output", str(out)]
        rc = main()
    finally:
        _sys.argv = old_argv

    assert rc == 0
    assert out.is_file()


if __name__ == "__main__":
    pytest.main([__file__])
