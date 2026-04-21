import unittest

from vibe_code_scanner.dedupe import dedupe_findings
from vibe_code_scanner.models import Category, Confidence, NormalizedFinding, Severity


class DedupeTests(unittest.TestCase):
    def test_dedupe_merges_overlapping_duplicate_findings(self) -> None:
        findings = [
            NormalizedFinding(
                file_path="src/app.py",
                chunk_ids=[1],
                title="Potential command injection",
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                line_start=10,
                line_end=12,
                explanation="User input is passed into a shell command.",
                evidence="subprocess.run(cmd, shell=True)",
                remediation="Avoid shell=True and pass an argument list.",
            ),
            NormalizedFinding(
                file_path="src/app.py",
                chunk_ids=[2],
                title="Potential command injection",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                line_start=11,
                line_end=13,
                explanation="Untrusted input appears to flow into shell execution.",
                evidence="shell=True with user-controlled content",
                remediation="Use subprocess.run([...], shell=False).",
            ),
        ]

        deduped = dedupe_findings(findings)

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity.value, "high")
        self.assertEqual(deduped[0].confidence.value, "high")
        self.assertEqual(deduped[0].chunk_ids, [1, 2])


if __name__ == "__main__":
    unittest.main()
