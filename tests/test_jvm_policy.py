import unittest

from fidb_poc.jvm_policy import java_options


class JvmPolicyTests(unittest.TestCase):
    def test_equivalent_inherited_heap_is_not_duplicated(self):
        result = java_options(4096, None, inherited="-Xms256m -Xmx4g")

        self.assertEqual(result, "-Xms256m -Xmx4g")

    def test_conflicting_inherited_heap_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "conflicts"):
            java_options(4096, None, inherited="-Xmx8g")

    def test_unbounded_choice_preserves_inherited_policy(self):
        result = java_options(None, None, inherited="-XX:ActiveProcessorCount=4")

        self.assertEqual(result, "-XX:ActiveProcessorCount=4")

    def test_equivalent_ghidra_core_limit_is_not_duplicated(self):
        result = java_options(None, 4, inherited="-Dcpu.core.limit=4")

        self.assertEqual(result, "-Dcpu.core.limit=4")


if __name__ == "__main__":
    unittest.main()
