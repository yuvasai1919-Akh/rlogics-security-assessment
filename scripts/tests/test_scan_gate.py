"""Tests for scan_gate.py. Run: python3 -m unittest discover -s scripts/tests -v"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import scan_gate  # noqa: E402

SAMPLES = HERE.parent / "samples"
TODAY = "2026-10-23"  # fixed so exception-expiry tests are deterministic


def run(*extra):
    """Run main() and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = scan_gate.main(["--today", TODAY, *extra])
    return code, out.getvalue(), err.getvalue()


class ScanGateTests(unittest.TestCase):
    def test_critical_with_fix_fails(self):
        code, out, _ = run("--trivy", str(SAMPLES / "trivy_critical_fixable.json"))
        self.assertEqual(code, scan_gate.EXIT_POLICY_FAIL)
        self.assertIn("CVE-2099-0001", out)
        self.assertIn("**FAIL**", out)

    def test_threshold_is_configurable(self):
        # HIGH threshold blocks the HIGH-with-fix finding as well
        _, out, _ = run("--trivy", str(SAMPLES / "trivy_critical_fixable.json"), "--fail-on", "HIGH")
        self.assertIn("BLOCK 2", out)

    def test_unfixed_critical_does_not_block_by_default(self):
        code, out, _ = run("--trivy", str(SAMPLES / "trivy_unfixed_only.json"))
        self.assertEqual(code, scan_gate.EXIT_OK)
        self.assertIn("no fix available", out)

    def test_unfixed_critical_blocks_when_policy_says_so(self):
        code, _, _ = run("--trivy", str(SAMPLES / "trivy_unfixed_only.json"), "--no-only-fixable")
        self.assertEqual(code, scan_gate.EXIT_POLICY_FAIL)

    def test_clean_report_passes(self):
        code, out, _ = run("--trivy", str(SAMPLES / "trivy_clean.json"))
        self.assertEqual(code, scan_gate.EXIT_OK)
        self.assertIn("**PASS**", out)

    def test_secret_blocks_and_value_is_not_printed(self):
        code, out, _ = run("--trivy", str(SAMPLES / "trivy_secret.json"))
        self.assertEqual(code, scan_gate.EXIT_POLICY_FAIL)
        self.assertNotIn("GITHUB_TOKEN", out)  # Match field must never be echoed

    def test_active_exception_downgrades_to_excepted(self):
        code, out, _ = run("--trivy", str(SAMPLES / "trivy_critical_fixable.json"),
                           "--exceptions", str(SAMPLES / "exceptions.json"))
        self.assertEqual(code, scan_gate.EXIT_OK)
        self.assertIn("EXCEPTED", out)

    def test_expired_exception_is_enforced_again(self):
        code, out, _ = run("--trivy", str(SAMPLES / "trivy_critical_fixable.json"),
                           "--exceptions", str(SAMPLES / "exceptions_expired.json"))
        self.assertEqual(code, scan_gate.EXIT_POLICY_FAIL)
        self.assertIn("Expired exceptions", out)

    def test_exception_missing_required_fields_is_input_error(self):
        code, _, err = run("--trivy", str(SAMPLES / "trivy_critical_fixable.json"),
                           "--exceptions", str(SAMPLES / "exceptions_invalid.json"))
        self.assertEqual(code, scan_gate.EXIT_INPUT_ERROR)
        self.assertIn("missing required", err)

    def test_malformed_json_is_input_error_not_a_pass(self):
        code, _, err = run("--trivy", str(SAMPLES / "malformed.json"))
        self.assertEqual(code, scan_gate.EXIT_INPUT_ERROR)
        self.assertIn("not valid JSON", err)

    def test_missing_file_is_input_error(self):
        code, _, err = run("--trivy", str(SAMPLES / "does_not_exist.json"))
        self.assertEqual(code, scan_gate.EXIT_INPUT_ERROR)
        self.assertIn("cannot read", err)

    def test_non_trivy_json_is_input_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / "bogus.json"
            bogus.write_text('{"hello": "world"}', encoding="utf-8")
            code, _, err = run("--trivy", str(bogus))
        self.assertEqual(code, scan_gate.EXIT_INPUT_ERROR)
        self.assertIn("does not look like Trivy JSON", err)

    def test_csv_and_markdown_outputs_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            md, csv_path = Path(tmp) / "r.md", Path(tmp) / "r.csv"
            run("--trivy", str(SAMPLES / "trivy_critical_fixable.json"),
                "--markdown", str(md), "--csv", str(csv_path))
            self.assertTrue(md.read_text().startswith("# Scan gate result"))
            self.assertIn("decision,kind,id", csv_path.read_text())


if __name__ == "__main__":
    unittest.main()
