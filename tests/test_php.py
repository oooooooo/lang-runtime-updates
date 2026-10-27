import unittest
from pathlib import Path

from langsec.sources.php import GHSA_PAGE_CVE, _ghsa_only

FIXTURES = Path(__file__).parent / "fixtures"


class GhsaTest(unittest.TestCase):
    def test_only_ghsa_lines_without_cve(self):
        section = (FIXTURES / "php_changelog_8.5.12.html").read_text()
        self.assertEqual(_ghsa_only(section), {"GHSA-w8hw-w9fx-j79w", "GHSA-6wmf-4rv5-p3rp"})

    def test_cve_from_advisory_page(self):
        m = GHSA_PAGE_CVE.search((FIXTURES / "ghsa_page_with_cve.html").read_text())
        self.assertEqual(m.group(1), "CVE-2026-109618")

    def test_advisory_page_without_cve(self):
        self.assertIsNone(GHSA_PAGE_CVE.search((FIXTURES / "ghsa_page_no_cve.html").read_text()))


if __name__ == "__main__":
    unittest.main()
