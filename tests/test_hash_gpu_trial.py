import importlib.util
import unittest

from fidb_poc.hash_gpu_trial import SENTINEL, _cpu_probe, _shader


@unittest.skipUnless(importlib.util.find_spec("numpy"), "GPU extra is not installed")
class HashGpuTrialTests(unittest.TestCase):
    def test_cpu_packed_probe_preserves_exact_key_identity(self):
        import numpy as np

        reference = np.array(
            [
                [0, 0, 1, 0, 2, 3, 4],
                [0, 0, 5, 0, 6, 7, 8],
                [1, 0, 1, 0, 2, 3, 4],
            ],
            dtype=np.uint32,
        )
        queries = np.array(
            [
                [0, 0, 1, 0, 2, 3, 4],
                [0, 0, 2, 0, 2, 3, 4],
                [1, 0, 1, 0, 2, 3, 4],
            ],
            dtype=np.uint32,
        )

        self.assertEqual(
            _cpu_probe(reference, queries).tolist(),
            [0, SENTINEL, 2],
        )

    def test_shader_pins_bounds_and_workgroup_size(self):
        shader = _shader(17, 9, 256)

        self.assertIn("REFERENCE_COUNT: u32 = 17u", shader)
        self.assertIn("QUERY_COUNT: u32 = 9u", shader)
        self.assertIn("@compute @workgroup_size(256)", shader)


if __name__ == "__main__":
    unittest.main()
