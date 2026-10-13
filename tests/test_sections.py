import unittest

from parser.sections import parse_sections


class ParseSectionsTests(unittest.TestCase):
    def test_dynamic_database_markers_and_labeled_fra(self) -> None:
        parsed = parse_sections(
            "check PF2\n[DB OUZELUM]\nDatabase Connection Successful.\n"
            "[FRA LIVE]\nNAME SPACE_LIMIT SPACE_USED\n+RECO 100 90\n"
        )

        self.assertEqual([section.name for section in parsed.sections], ["DB OUZELUM", "FRA"])
        self.assertIn("SPACE_LIMIT", parsed.sections[1].content)
        self.assertEqual(parsed.unparsed_content, "check PF2")

    def test_untitled_fra_sql_output_is_detected(self) -> None:
        parsed = parse_sections("check PF2\nNAME SPACE_LIMIT SPACE_USED\n+RECO 100 90\n")

        self.assertEqual(len(parsed.sections), 1)
        self.assertEqual(parsed.sections[0].name, "FRA")
        self.assertEqual(parsed.unparsed_content, "check PF2")

    def test_compact_database_marker_is_normalized(self) -> None:
        parsed = parse_sections("[DBLIVE]\nDatabase Connection Successful.\n")

        self.assertEqual(parsed.sections[0].name, "DB LIVE")

    def test_unknown_bracketed_content_is_preserved_as_unparsed(self) -> None:
        parsed = parse_sections("[NEW CHECK]\nFAILED: new check\n")

        self.assertEqual(parsed.sections, [])
        self.assertIn("[NEW CHECK]", parsed.unparsed_content)
        self.assertIn("FAILED: new check", parsed.unparsed_content)


if __name__ == "__main__":
    unittest.main()