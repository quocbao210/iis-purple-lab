"""Portable client-boundary checks; these never start the app or a command."""
import argparse
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("scenario_run", Path(__file__).with_name("run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class HarnessTests(unittest.TestCase):
    def test_redirects_cannot_leave_authorised_origin(self):
        with self.assertRaises(ValueError):
            run.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com/")

    def test_targets_are_literal_loopback_with_explicit_port(self):
        self.assertEqual(run.validate_base_url("http://127.0.0.1:5080/"), "http://127.0.0.1:5080")
        for value in ["https://example.com", "http://example.com:5080", "http://127.0.0.1.evil:80",
                      "http://127.0.0.1:80/path", "http://u:p@127.0.0.1:80", "http://localhost:80", "http://127.0.0.1"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                run.validate_base_url(value)

    def test_payloads_fit_application_bound_and_use_fixed_local_services(self):
        self.assertLessEqual(len(run.B_TITLE), 512)
        self.assertLessEqual(len(run.C_TITLE), 512)
        self.assertIn("whoami", run.B_TITLE)
        self.assertIn("http://127.0.0.1:8099/evidence", run.C_TITLE)
        self.assertIn("$env:PURPLELAB_WORK", run.C_TITLE)
        self.assertNotIn("-EncodedCommand", run.C_TITLE)


if __name__ == "__main__":
    unittest.main()
