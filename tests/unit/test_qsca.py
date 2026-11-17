"""Unit tests for qsca CLI helpers that do not call AWS."""

import importlib.machinery
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("qsca_cli", str(ROOT / "qsca"))
spec = importlib.util.spec_from_loader("qsca_cli", loader)
qsca = importlib.util.module_from_spec(spec)
loader.exec_module(qsca)


class ChatBindingTest(unittest.TestCase):
    BASE = "https://chat.example.com/"

    def test_accepts_exact_deployment_and_analysis(self):
        url = "https://chat.example.com/?analysis=copy-1&p.station=<<$station>>"
        self.assertTrue(qsca.chat_binding(url, self.BASE, "copy-1"))

    def test_rejects_stale_duplicate_or_missing_analysis(self):
        for url in (
            "https://chat.example.com/?analysis=original",
            "https://chat.example.com/?analysis=copy-1&analysis=original",
            "https://chat.example.com/?p.station=all",
        ):
            self.assertFalse(qsca.chat_binding(url, self.BASE, "copy-1"), url)

    def test_rejects_another_endpoint_path_or_fragment(self):
        for url in (
            "https://other.example.com/?analysis=copy-1",
            "https://chat.example.com/other?analysis=copy-1",
            "https://chat.example.com/?analysis=copy-1#ignored",
            None,
        ):
            self.assertFalse(qsca.chat_binding(url, self.BASE, "copy-1"), url)


if __name__ == "__main__":
    unittest.main()
