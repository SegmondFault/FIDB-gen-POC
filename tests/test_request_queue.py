import csv
import tempfile
import unittest
from pathlib import Path

from fidb_poc.request_queue import record_missing_requests


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


class RequestQueueTests(unittest.TestCase):
    def test_creates_a_human_readable_pending_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "recipe_requests/pending.csv"
            record_missing_requests(
                path,
                ("libpng",),
                priority=1,
                routes=("linux-x86_64-gnu-gcc",),
                now="2026-08-19T10:00:00+00:00",
            )

            self.assertEqual(
                read_rows(path),
                [
                    {
                        "library_request": "libpng",
                        "priority": "1",
                        "status": "pending",
                        "resolution_lane": "source_discovery",
                        "requested_routes": "linux-x86_64-gnu-gcc",
                        "first_requested_utc": "2026-08-19T10:00:00+00:00",
                        "last_requested_utc": "2026-08-19T10:00:00+00:00",
                        "request_count": "1",
                        "candidate_version": "",
                        "candidate_source_url": "",
                        "candidate_sha256": "",
                        "notes": "",
                    }
                ],
            )

    def test_repeated_requests_merge_and_promote_priority(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "recipe_requests/pending.csv"
            record_missing_requests(
                path,
                ("LibPNG",),
                priority=2,
                routes=("linux-x86_64-gnu-gcc",),
                now="2026-08-19T10:00:00+00:00",
            )
            record_missing_requests(
                path,
                ("libpng",),
                priority=0,
                routes=("linux-x86_64-gnu-gcc",),
                now="2026-08-19T11:00:00+00:00",
            )

            rows = read_rows(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["priority"], "0")
            self.assertEqual(rows[0]["request_count"], "2")
            self.assertEqual(
                rows[0]["requested_routes"],
                "linux-x86_64-gnu-gcc",
            )
            self.assertEqual(rows[0]["last_requested_utc"], "2026-08-19T11:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
