"""Lightweight regression tests for CocoScanner core validation/filter logic."""
import importlib.util
import unittest
from pathlib import Path

APP_PATH = Path(__file__).resolve().parents[1] / "cocoscanner.py"
spec = importlib.util.spec_from_file_location("CocoScanner", APP_PATH)
ns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ns)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.app = object.__new__(ns.App)

    def test_safe_private_subnet(self):
        self.assertEqual(ns.safe_net("192.168.1.12/24"), "192.168.1.0/24")
        self.assertEqual(ns.safe_net("10.0.0.5/24"), "10.0.0.0/24")

    def test_safe_subnet_rejects_public_and_oversized(self):
        with self.assertRaises(ValueError): ns.safe_net("8.8.8.0/24")
        with self.assertRaises(ValueError): ns.safe_net("10.0.0.0/16")

    def test_normalize_ip_and_domain(self):
        self.assertEqual(self.app._normalize_ioc("IP", "192.0.2.1"), ("ip", "192.0.2.1"))
        self.assertEqual(self.app._normalize_ioc("domain", "Login.Example.org."), ("domain", "login.example.org"))

    def test_normalize_rejects_invalid_indicator(self):
        for typ, value in [("ip", "999.1.1.1"), ("domain", "not a domain"), ("url", "https://example.org")]:
            with self.subTest(typ=typ, value=value), self.assertRaises(ValueError):
                self.app._normalize_ioc(typ, value)

    def test_packet_filter_protocol_ip_port_and_size(self):
        rec = {"src":"192.168.1.10", "dst":"1.1.1.1", "protocol":"TCP", "src_port":51515,
               "dst_port":443, "length":1200, "tcp_flags":"SA", "dns":"", "summary":"TCP packet"}
        for query in ("tcp", "host=192.168.1.10", "dstport=443", "tcp and dstport=443", "len>1000", "flags=S"):
            with self.subTest(query=query): self.assertTrue(self.app.packet_matches_filter(rec, query))
        for query in ("udp", "host=192.168.1.20", "dstport=80", "len>1500", "flags=F"):
            with self.subTest(query=query): self.assertFalse(self.app.packet_matches_filter(rec, query))

    def test_packet_filter_free_text_fallback(self):
        rec = {"src":"192.168.1.10", "dst":"1.1.1.1", "protocol":"TCP", "src_port":1,
               "dst_port":443, "length":100, "tcp_flags":"S", "dns":"", "summary":"TLS Client Hello"}
        self.assertTrue(self.app.packet_matches_filter(rec, "client hello"))
        self.assertFalse(self.app.packet_matches_filter(rec, "no-such-token"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
