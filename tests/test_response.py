import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.response import ResponseManager  # noqa: E402
from src.response import backends as B  # noqa: E402


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


class FakeBackend:
    def __init__(self):
        self.calls = []

    def block(self, ip, ttl):
        self.calls.append(("block", ip))
        return True, None

    def unblock(self, ip):
        self.calls.append(("unblock", ip))
        return True, None


def mk(tmp_path, mode="auto", **extra):
    clk, be = Clock(), FakeBackend()
    m = ResponseManager(str(tmp_path / "c.json"), str(tmp_path / "audit.jsonl"), clock=clk,
                        backend=be, own_ips={"10.0.0.5"}, notifier=lambda t: None)
    m.update_config(dict({"mode": mode}, **extra))
    return m, clk, be


def flow(ip="8.8.8.8", family="BruteForce", **kw):
    d = {"id": "a1", "verdict": "attack", "severity": "critical", "confidence": "high", "votes": 3,
         "family": family, "mode": "x", "src": {"ip": ip}, "risk": 90}
    d.update(kw)
    return d


def test_defaults(tmp_path):
    m = ResponseManager(str(tmp_path / "none.json"), str(tmp_path / "a.jsonl"))
    c = m.config()
    assert c["mode"] == "suggest" and c["backend"] == "dry-run" and c["ttlMinutes"] == 60


def test_none_cases(tmp_path):
    m, _, _ = mk(tmp_path)
    assert m.evaluate(flow(verdict="normal"))["action"] == "none"
    assert m.evaluate(flow(ip=None, src={}))["action"] == "none"
    assert m.evaluate(flow(ip="127.0.0.1"))["action"] == "none"
    assert m.evaluate(flow(ip="10.0.0.5"))["action"] == "none"
    m.update_config({"allowlist": ["8.8.8.0/24"]})
    assert m.evaluate(flow())["reason"] == "allowlisted"
    assert m.evaluate(None)["action"] == "none"


def test_manual_block_refused(tmp_path):
    m, _, be = mk(tmp_path)
    for ip in ("127.0.0.1", "10.0.0.5", "169.254.1.1", "255.255.255.255"):
        assert m.block(ip, "x")["status"] == "failed"
    assert be.calls == [] and m.blocks() == []


def test_ddos_suggest(tmp_path):
    m, _, be = mk(tmp_path)
    r = m.evaluate(flow(family="DDoS"))
    assert r["action"] == "suggest" and "upstream protection" in r["reason"] and not be.calls


def test_modes(tmp_path):
    m, _, be = mk(tmp_path, "suggest")
    assert m.evaluate(flow())["action"] == "suggest" and not be.calls
    m.update_config({"mode": "approve"})
    assert m.evaluate(flow())["action"] == "pending"
    assert len(m.pending()) == 1 and not be.calls
    assert m.approve("8.8.8.8")["status"] == "active"
    assert m.pending() == [] and len(m.blocks()) == 1
    m.update_config({"mode": "auto"})
    assert m.evaluate(flow(ip="1.1.1.1"))["action"] == "blocked"
    m.update_config({"mode": "approve"})
    m.evaluate(flow(ip="2.2.2.2"))
    assert m.reject("2.2.2.2") and m.pending() == []


def test_auto_rules_and_novel(tmp_path):
    m, _, be = mk(tmp_path)
    assert m.evaluate(flow(family="Novel"))["action"] == "suggest"
    assert m.evaluate(flow(severity="medium"))["action"] == "suggest"
    assert m.evaluate(flow(votes=1))["action"] == "suggest"
    assert m.evaluate(flow(family="Weird"))["action"] == "suggest"
    assert not be.calls


def test_rate_limit(tmp_path):
    notes = []
    m, clk, be = mk(tmp_path, maxBlocksPerMinute=2)
    m._notifier = notes.append
    assert m.evaluate(flow(ip="1.0.0.1"))["action"] == "blocked"
    assert m.evaluate(flow(ip="1.0.0.2"))["action"] == "blocked"
    assert m.evaluate(flow(ip="1.0.0.3"))["action"] == "suggest"
    assert notes and len(m.blocks()) == 2
    clk.t += 61
    assert m.evaluate(flow(ip="1.0.0.3"))["action"] == "blocked"


def test_ttl_expiry(tmp_path):
    m, clk, be = mk(tmp_path)
    m.block("9.9.9.9", "r", ttl_minutes=1)
    assert len(m.blocks()) == 1
    clk.t += 61
    assert m.blocks() == [] and ("unblock", "9.9.9.9") in be.calls


def test_persistence(tmp_path):
    m, clk, be = mk(tmp_path, "approve")
    m.block("9.9.9.9", "r")
    m.evaluate(flow(ip="7.7.7.7"))
    m2 = ResponseManager(str(tmp_path / "c.json"), str(tmp_path / "audit.jsonl"), clock=clk,
                         backend=FakeBackend(), own_ips=set())
    assert [b["ip"] for b in m2.blocks()] == ["9.9.9.9"]
    assert [b["ip"] for b in m2.pending()] == ["7.7.7.7"]
    assert m2.config()["mode"] == "approve"


def test_config_validation(tmp_path):
    m, _, _ = mk(tmp_path)
    for bad in ({"mode": "x"}, {"backend": "x"}, {"allowlist": ["nope"]}, {"ttlMinutes": -1}, {"foo": 1}):
        with pytest.raises(ValueError):
            m.update_config(bad)
    assert m.config()["mode"] == "auto"
    m.update_config({"notify": {"slackWebhook": "https://x"}})
    assert m.config()["notify"]["slackWebhook"] == "***"


def test_audit(tmp_path):
    m, _, _ = mk(tmp_path)
    m.block("9.9.9.9", "why")
    m.unblock("9.9.9.9")
    a = m.audit()
    assert [e["action"] for e in a][:2] == ["unblock", "block"]
    for k in ("time", "action", "ip", "source", "reason", "backend", "result"):
        assert k in a[0]
    with open(tmp_path / "audit.jsonl") as f:
        assert all(json.loads(l) for l in f)


def test_backends_no_crash():
    class P:
        returncode, stderr, stdout = 1, "boom", ""
    assert B.PfBackend(runner=lambda *a, **k: P, is_root=lambda: False).block("1.2.3.4", 5)[0] is False
    ok, err = B.PfBackend(runner=lambda *a, **k: P, is_root=lambda: True).block("1.2.3.4", 5)
    assert not ok and "boom" in err
    def raiser(*a, **k):
        raise OSError("nope")
    assert B.NftBackend(runner=raiser).block("1.2.3.4", 5)[0] is False
    assert B.CloudflareBackend().block("1.2.3.4", 5)[0] is False  # no env, no network


def test_failed_backend_status(tmp_path):
    m, _, be = mk(tmp_path)
    be.block = lambda ip, ttl: (False, "denied")
    b = m.block("9.9.9.9", "r")
    assert b["status"] == "failed" and b["error"] == "denied" and m.blocks() == []
