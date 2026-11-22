import argparse
import tempfile
import unittest
from pathlib import Path

from health import make_probe, respond, verified
from pool import Pool, inventory


class HealthTests(unittest.TestCase):
    def test_fresh_domain_and_pair_key(self):
        domain = "tun.example.test"
        packet = make_probe(domain)
        key = b"test-key"
        answer = respond(packet, domain, key)
        self.assertTrue(verified(packet, answer, key))
        self.assertFalse(verified(packet, answer, b"other"))
        self.assertFalse(verified(make_probe(domain), answer, key))
        self.assertIsNone(respond(packet, "different.example.test", key))

    def test_30000_entries_dedup_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "resolvers.txt")
            rows = [f"10.1.{n // 256}.{n % 256}" for n in range(30000)]
            p.write_text("\n".join(rows + rows[:100]) + "\n")
            self.assertEqual(len(inventory(p)), 30000)
            with p.open("a") as f:
                f.write("10.2.0.1\n")
            with self.assertRaises(ValueError):
                inventory(p)

    def test_remove_after_three_failures_and_restore_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            k = Path(tmp, "key")
            k.write_text("test-key")
            p = Pool(argparse.Namespace(key_file=k))
            p.healthy["127.0.0.2"] = ("udp", 0.01)
            p.refresh()
            for _ in range(2):
                p.failed("127.0.0.2")
            self.assertIn("127.0.0.2", p.slots)
            p.failed("127.0.0.2")
            self.assertNotIn("127.0.0.2", p.slots)
            p.healthy["127.0.0.2"] = ("tcp", 0.03)
            p.refresh()
            self.assertIn("127.0.0.2", p.slots)
