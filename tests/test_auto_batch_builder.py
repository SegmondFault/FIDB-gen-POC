import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from fidb_poc.auto_batch_builder import (
    _pack_route_bundles,
    _route_bundles,
    _render_plan,
    _render_queue,
    check_auto_batches,
    write_auto_batches,
)
from fidb_poc.operations_policy import load_operations_policy
from fidb_poc.plan_request import resolve_plan


class AutoBatchBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_packing_preserves_stable_route_units_and_duration_ceiling(self):
        bundles = [
            {
                "source_id": "a",
                "route_id": f"route-{index}",
                "estimated_hours": hours,
            }
            for index, hours in enumerate((0.4, 0.4, 0.3, 0.5, 0.2), start=1)
        ]

        chunks = _pack_route_bundles(
            bundles,
            target_hours=0.75,
            max_hours=1.0,
        )

        self.assertEqual(
            [row["route_id"] for chunk in chunks for row in chunk],
            [row["route_id"] for row in bundles],
        )
        self.assertTrue(
            all(
                sum(float(row["estimated_hours"]) for row in chunk) <= 1.0
                for chunk in chunks
            )
        )

    def test_route_bundles_omit_recipe_inapplicable_routes(self):
        time_plan = {
            "blocks": [
                {
                    "items": [
                        {
                            "rank": 1,
                            "source_id": "demo",
                            "label": "Demo",
                            "version": "1.0",
                            "batch_authority": "batches/demo.toml",
                            "executions": 2,
                            "estimated_hours": 1.0,
                        }
                    ]
                }
            ]
        }
        raw_batch = {
            "libraries": [{"id": "demo", "version": "1.0", "recipe_id": "demo@1.0"}]
        }
        projected = {
            "libraries": [
                {
                    "id": "demo",
                    "version": "1.0",
                    "recipe_id": "demo@1.0",
                    "applicable_route_ids": ["route-a"],
                }
            ]
        }
        with (
            patch(
                "fidb_poc.auto_batch_builder.load_width_batch", return_value=raw_batch
            ),
            patch(
                "fidb_poc.auto_batch_builder.project_width_batch_readiness",
                return_value=projected,
            ),
            patch(
                "fidb_poc.auto_batch_builder._ordered_width_axes",
                return_value=(("route-a", "route-b"), ("o2", "o3")),
            ),
            patch(
                "fidb_poc.auto_batch_builder._reviewed_recipe_projections",
                return_value=[],
            ),
        ):
            bundles = _route_bundles(self.root, time_plan)

        self.assertEqual(len(bundles), 1)
        self.assertEqual(bundles[0]["route_id"], "route-a")
        self.assertEqual(bundles[0]["treatment_ids"], ["o2", "o3"])

    def test_one_route_plan_keeps_all_treatments_and_resolves(self):
        chunk = {
            "id": "auto-test-chunk-001",
            "executions": 6,
            "groups": [
                {
                    "batch_authority": "batches/c-next-nine-mega-width.toml",
                    "recipe_id": "sqlite@3.53.4",
                    "route_ids": ["linux-x86-64-gcc-12"],
                    "treatment_ids": [
                        "baseline_o2",
                        "optimization_o0",
                        "optimization_o3",
                        "optimization_os",
                        "frame_pointer_omitted",
                        "stack_protector_strong",
                    ],
                }
            ],
        }
        payload = _render_plan(chunk)
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            path = Path(temporary) / "chunk.toml"
            path.write_text(payload, encoding="utf-8")
            resolved = resolve_plan(path, self.root)

        self.assertEqual(resolved["summary"]["planned_cells"], 6)
        self.assertEqual(
            {row["base_cell"].split(":")[-1] for row in resolved["queue_preview"]},
            set(chunk["groups"][0]["treatment_ids"]),
        )

    def test_generated_queue_is_disarmed_and_chains_finished_chunks(self):
        document = {
            "id": "campaign",
            "performance_profile": {
                "id": "reference-host-94g-balanced",
                "settings": {"workers": 20},
            },
            "chunks": [
                {
                    "id": "chunk-001",
                    "name": "chunk one",
                    "plan": "plans/chunk-001.toml",
                    "plan_sha256": "a" * 64,
                    "queue_digest": "b" * 64,
                    "executions": 6,
                }
            ],
        }
        source = tomllib.loads(
            (self.root / "plans/c-top10-nonapple-width-v2-queue-policy.toml").read_text(
                encoding="utf-8"
            )
        )

        payload = _render_queue(document, source)
        queue = tomllib.loads(payload)
        policy = load_operations_policy(queue, self.root)

        self.assertFalse(queue["queue"]["armed"])
        self.assertEqual(queue["queue"]["max_workers"], 20)
        self.assertEqual(queue["schedule"]["start"], "00:00")
        self.assertEqual(queue["schedule"]["stop_claiming"], "05:30")
        self.assertTrue(policy.schedule.finish_started_batch)
        self.assertTrue(policy.schedule.chain_batches)
        self.assertTrue(policy.schedule.tail_fill.enabled)
        self.assertEqual(policy.schedule.tail_fill.max_active_blocks, 2)
        self.assertNotIn("hard_cutoff", queue["schedule"])

        canary = tomllib.loads(_render_queue(document, source, canary_only=True))
        self.assertFalse(canary["queue"]["armed"])
        self.assertFalse(canary["schedule"]["enabled"])
        self.assertFalse(canary["schedule"]["chain_batches"])
        self.assertFalse(canary["schedule"]["tail_fill"]["enabled"])
        self.assertEqual(canary["schedule"]["tail_fill"]["max_active_blocks"], 1)
        self.assertEqual(canary["queue"]["batch_order"], ["chunk-001"])
        self.assertEqual(len(canary["batch"]), 1)

    def test_generated_plan_carries_the_current_qualification_seal(self):
        chunk = {
            "id": "auto-test-chunk-001",
            "executions": 6,
            "groups": [
                {
                    "batch_authority": "batches/c-11-20-mega-width.toml",
                    "recipe_id": "harfbuzz@14.4.0",
                    "route_ids": ["linux-x86-64-gcc"],
                    "treatment_ids": ["baseline_o2"],
                }
            ],
        }
        gate = {
            "batch_id": "batch-c11-20",
            "batch_digest": "a" * 64,
            "authority_path": "qualification/c11-c20.toml",
            "authority_sha256": "b" * 64,
            "pipeline_authority_path": "qualification/pipeline.toml",
            "pipeline_authority_sha256": "c" * 64,
            "input_digest": "d" * 64,
            "qualification_digest": "e" * 64,
            "evidence_path": "qualification/evidence/c11-c20.json",
            "evidence_sha256": "f" * 64,
        }

        plan = tomllib.loads(_render_plan(chunk, [gate]))

        self.assertEqual(plan["qualification_gate"], [gate])

    def test_write_and_check_are_bounded_to_declared_generated_files(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            relative = Path(temporary).relative_to(self.root) / "generated.toml"
            document = {"rendered_files": {str(relative): "value = 1\n"}}

            write_auto_batches(document, self.root)
            current = check_auto_batches(document, self.root)
            (self.root / relative).write_text("value = 2\n", encoding="utf-8")
            drifted = check_auto_batches(document, self.root)

        self.assertEqual(current["state"], "current")
        self.assertEqual(drifted["state"], "drifted")
        self.assertEqual(drifted["mismatches"][0]["reason"], "content-drift")


if __name__ == "__main__":
    unittest.main()
