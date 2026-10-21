"""Dreiwege-Merge für *.tfvars.json."""

import json
import unittest

from tofu_agent_gate.jsonmerge import MISSING, MergeConflict, merge3, merge_texts, style_of


class Merge3Test(unittest.TestCase):
    def test_both_add_different_keys(self):
        base = {"p": {"a": 1}}
        self.assertEqual(merge3(base, {"p": {"a": 1, "b": 2}}, {"p": {"a": 1, "c": 3}}),
                         {"p": {"a": 1, "b": 2, "c": 3}})

    def test_one_side_changes_other_adds(self):
        base = {"a": {"v": 1}}
        self.assertEqual(merge3(base, {"a": {"v": 2}}, {"a": {"v": 1}, "b": {"v": 9}}),
                         {"a": {"v": 2}, "b": {"v": 9}})

    def test_delete_on_one_side(self):
        base = {"a": 1, "b": 2}
        self.assertEqual(merge3(base, {"a": 1}, {"a": 1, "b": 2, "c": 3}), {"a": 1, "c": 3})

    def test_same_key_changed_differently_conflicts_with_path(self):
        with self.assertRaises(MergeConflict) as cm:
            merge3({"r": {"x": {"port": "22"}}}, {"r": {"x": {"port": "23"}}}, {"r": {"x": {"port": "24"}}})
        self.assertEqual(cm.exception.path, "/r/x/port")

    def test_both_add_same_key_same_value(self):
        self.assertEqual(merge3({}, {"k": 1}, {"k": 1}), {"k": 1})

    def test_both_add_same_key_different_value(self):
        with self.assertRaises(MergeConflict):
            merge3({}, {"k": 1}, {"k": 2})

    def test_scalar_lists_as_sets(self):
        base = ["Aluhut", "git", "tor"]
        ours = ["Aluhut", "git", "iac", "tor"]
        theirs = ["Aluhut", "git", "linkedin"]  # fügt hinzu und entfernt tor
        self.assertEqual(merge3(base, ours, theirs), ["Aluhut", "git", "iac", "linkedin"])

    def test_list_of_objects_conflicts(self):
        with self.assertRaises(MergeConflict):
            merge3([{"a": 1}], [{"a": 2}], [{"a": 3}])

    def test_missing_base_file_added_both_sides(self):
        self.assertEqual(merge3(MISSING, {"a": 1}, {"b": 2}), {"a": 1, "b": 2})


class TextTest(unittest.TestCase):
    def test_style_kept_unsorted_and_umlauts(self):
        ours = json.dumps({"z": {"name": "Büro"}, "a": 1}, indent=2, ensure_ascii=False) + "\n"
        base = json.dumps({"a": 1}, indent=2) + "\n"
        theirs = json.dumps({"a": 1, "m": 2}, indent=2) + "\n"
        out = merge_texts(base, ours, theirs)
        self.assertEqual(list(json.loads(out)), ["z", "a", "m"])
        self.assertIn("Büro", out)

    def test_style_sorted(self):
        text = json.dumps({"b": 1, "a": 2}, indent=2, sort_keys=True) + "\n"
        self.assertTrue(style_of(text)["sort_keys"])


if __name__ == "__main__":
    unittest.main()
