import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class TestEstrutura(unittest.TestCase):
    def test_agentes(self):
        self.assertEqual(len(list((ROOT/".claude/agents").glob("*.md"))),10)
    def test_skills(self):
        self.assertEqual(len(list((ROOT/".claude/skills").glob("*/SKILL.md"))),19)
    def test_frontmatter(self):
        files = list((ROOT/".claude/agents").glob("*.md"))
        files += list((ROOT/".claude/skills").glob("*/SKILL.md"))
        for file in files:
            text = file.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"),
                            str(file))
            self.assertIn("description:", text)
            self.assertIn("## O — Objetivo", text)
