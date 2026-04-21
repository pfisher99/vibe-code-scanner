import unittest

from vibe_code_scanner.cli import main


class CliTests(unittest.TestCase):
    def test_main_rejects_root_and_repo_together(self) -> None:
        with self.assertRaises(SystemExit) as context:
            main([".", "--repo", "https://github.com/OWASP/NodeGoat"])
        self.assertEqual(context.exception.code, 2)

    def test_main_rejects_ref_without_repo(self) -> None:
        with self.assertRaises(SystemExit) as context:
            main(["--ref", "main"])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
