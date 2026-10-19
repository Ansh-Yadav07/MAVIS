"""MAVIS response (blocking) manager. Thread-safe, persistent, audited."""
import copy
import ipaddress
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

from . import backends as B

MODES = ("suggest", "approve", "auto")
BACKENDS = ("dry-run", "pf", "nftables", "cloudflare")
LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DDOS_REASON = "distributed attack: enable upstream protection (e.g. Cloudflare Under Attack mode)"
DEFAULT_CONFIG = {
    "mode": "suggest", "backend": "dry-run", "ttlMinutes": 60,
    "allowlist": ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"],
    "maxBlocksPerMinute": 10,
    "autoRules": {"minSeverity": "critical", "minConfidence": "high", "minVotes": 2,
                  "families": ["BruteForce", "PortScan", "WebAttack", "DoS", "Bot", "Infiltration"]},
    "notify": {"slackWebhook": None},
}


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _own_ips():
    out = set()
    try:
        out.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception:  # noqa: BLE001
        pass
    return out


class ResponseManager:
    def __init__(self, config_path="config/response.json", audit_path="results/response/audit.jsonl",
                 state_path=None, clock=time.time, backend=None, own_ips=None, notifier=None):
        self.config_path, self.audit_path = config_path, audit_path
        self.state_path = state_path or os.path.join(os.path.dirname(audit_path) or ".", "state.json")
        self.clock = clock
        self._lock = threading.RLock()
        self._own = set(own_ips) if own_ips is not None else _own_ips()
        self._notifier = notifier or self._notify
        self._backend_override = backend
        self._cfg = copy.deepcopy(DEFAULT_CONFIG)
        self._blocks, self._pending, self._recent = {}, {}, []
        try:
            with open(config_path) as f:
                self._cfg = self._validate(json.load(f), base=self._cfg)
        except FileNotFoundError:
            pass
        except Exception:  # noqa: BLE001
            self._cfg = copy.deepcopy(DEFAULT_CONFIG)
        try:
            with open(self.state_path) as f:
                st = json.load(f)
            self._blocks, self._pending = st.get("blocks", {}), st.get("pending", {})
        except Exception:  # noqa: BLE001
            pass
        self._backend = backend or B.make_backend(self._cfg["backend"])

    # ---- config
    @staticmethod
    def _validate(patch, base):
        cfg = copy.deepcopy(base)
        if not isinstance(patch, dict):
            raise ValueError("config must be an object")
        for k, v in patch.items():
            if k == "mode":
                if v not in MODES:
                    raise ValueError("unknown mode: %r" % (v,))
            elif k == "backend":
                if v not in BACKENDS:
                    raise ValueError("unknown backend: %r" % (v,))
            elif k in ("ttlMinutes", "maxBlocksPerMinute"):
                if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                    raise ValueError("%s must be a positive number" % k)
            elif k == "allowlist":
                if not isinstance(v, list):
                    raise ValueError("allowlist must be a list")
                for c in v:
                    try:
                        ipaddress.ip_network(c, strict=False)
                    except Exception:  # noqa: BLE001
                        raise ValueError("bad CIDR: %r" % (c,))
            elif k == "autoRules":
                if not isinstance(v, dict):
                    raise ValueError("autoRules must be an object")
                for s in ("minSeverity", "minConfidence"):
                    if s in v and v[s] not in LEVELS:
                        raise ValueError("bad %s: %r" % (s, v[s]))
                if "minVotes" in v and (not isinstance(v["minVotes"], int) or v["minVotes"] < 0):
                    raise ValueError("bad minVotes")
                if "families" in v and not isinstance(v["families"], list):
                    raise ValueError("families must be a list")
                v = dict(cfg["autoRules"], **v)
            elif k == "notify":
                if not isinstance(v, dict):
                    raise ValueError("notify must be an object")
                v = dict(cfg["notify"], **v)
            elif k.startswith("_"):
                continue
            else:
                raise ValueError("unknown config field: %s" % k)
            cfg[k] = v
        return cfg

    def config(self):
        with self._lock:
            c = copy.deepcopy(self._cfg)
        if c["notify"].get("slackWebhook"):
            c["notify"]["slackWebhook"] = "***"
        c["notify"]["slackWebhookEnv"] = bool(os.environ.get("MAVIS_SLACK_WEBHOOK"))
        return c

    def update_config(self, patch):
        patch = dict(patch or {})
        if (patch.get("notify") or {}).get("slackWebhook") == "***":
            patch["notify"] = {k: v for k, v in patch["notify"].items() if k != "slackWebhook"}
        with self._lock:
            new = self._validate(patch, self._cfg)
            if new["backend"] != self._cfg["backend"] and not self._backend_override:
                self._backend = B.make_backend(new["backend"])
            self._cfg = new
            try:
                os.makedirs(os.path.dirname(self.config_path) or ".", exist_ok=True)
                with open(self.config_path, "w") as f:
                    json.dump(new, f, indent=2)
            except OSError:
                pass
            self._log("config", "", "analyst", json.dumps(patch)[:200], "ok")
        return self.config()

    # ---- helpers
    def _log(self, action, ip, source, reason, result):
        rec = {"time": _iso(self.clock()), "action": action, "ip": ip, "source": source,
               "reason": reason, "backend": self._cfg["backend"], "result": result}
        try:
            os.makedirs(os.path.dirname(self.audit_path) or ".", exist_ok=True)
            with open(self.audit_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"blocks": self._blocks, "pending": self._pending}, f)
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    def _notify(self, text):
        if self._cfg["notify"].get("slackWebhook") and not os.environ.get("MAVIS_SLACK_WEBHOOK"):
            os.environ["MAVIS_SLACK_WEBHOOK"] = self._cfg["notify"]["slackWebhook"]
        B.notify_slack(text)

    def _tell(self, text):
        try:
            self._notifier(text)
        except Exception:  # noqa: BLE001
            pass

    def _protected(self, ip):
        """Return reason string if ip must never be blocked, else None."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return "invalid IP address"
        if a.is_loopback:
            return "loopback address"
        if a.is_multicast or a.is_unspecified or ip == "255.255.255.255":
            return "broadcast/multicast address"
        if ip in self._own:
            return "own machine address"
        for c in self._cfg["allowlist"]:
            if a.version == ipaddress.ip_network(c, strict=False).version and \
                    a in ipaddress.ip_network(c, strict=False):
                return "allowlisted"
        return None

    def _prune(self):
        now = self.clock()
        for ip in [i for i, b in self._blocks.items() if b.get("expiresTs") and b["expiresTs"] <= now]:
            ok, err = self._backend.unblock(ip)
            self._log("expire", ip, "system", "ttl elapsed", "ok" if ok else "error: %s" % err)
            del self._blocks[ip]
            self._save()

    # ---- public
    def evaluate(self, flow):
        try:
            return self._evaluate(flow or {})
        except Exception as e:  # noqa: BLE001
            return {"action": "none", "reason": "evaluate error: %s" % e}

    def _evaluate(self, f):
        if f.get("verdict") == "normal":
            return {"action": "none", "reason": "normal traffic"}
        ip = (f.get("src") or {}).get("ip")
        if not ip:
            return {"action": "none", "reason": "no source ip"}
        fam = f.get("family") or ""
        with self._lock:
            prot = self._protected(ip)
            if prot == "allowlisted":
                return {"action": "none", "reason": "allowlisted"}
            if prot:
                return {"action": "none", "reason": prot}
            if fam == "DDoS":
                return {"action": "suggest", "reason": DDOS_REASON}
            if ip in self._blocks:
                return {"action": "none", "reason": "already blocked"}
            mode, rules = self._cfg["mode"], self._cfg["autoRules"]
            reason = "%s %s (severity %s, confidence %s)" % (fam or "anomaly", f.get("verdict", ""),
                                                           f.get("severity"), f.get("confidence"))
            if mode == "suggest":
                return {"action": "suggest", "reason": "suggested: " + reason}
            if mode == "approve":
                if ip in self._pending:
                    return {"action": "pending", "reason": "awaiting approval"}
                self._pending[ip] = self._mk(ip, reason, None, "auto", f.get("id"), "pending")
                self._save()
                self._log("pending", ip, "auto", reason, "queued")
                self._tell("MAVIS: block of %s awaiting approval (%s)" % (ip, reason))
                return {"action": "pending", "reason": "awaiting approval: " + reason}
            # auto
            lv = lambda x: LEVELS.get(str(x).lower(), -1)  # noqa: E731
            met = (lv(f.get("severity")) >= lv(rules["minSeverity"])
                   and lv(f.get("confidence")) >= lv(rules["minConfidence"])
                   and (f.get("votes") if isinstance(f.get("votes"), (int, float)) else
                        len(f.get("votes") or [])) >= rules["minVotes"])
            if not met or fam == "Novel" or fam not in rules["families"]:
                return {"action": "suggest", "reason": "auto rules not met: " + reason}
            b = self._do_block(ip, reason, None, "auto", f.get("id"))
            if b["status"] == "active":
                return {"action": "blocked", "reason": reason}
            return {"action": "suggest", "reason": b.get("error") or "block failed"}

    def _mk(self, ip, reason, ttl, source, alert_id, status):
        now = self.clock()
        ttl = ttl or self._cfg["ttlMinutes"]
        return {"ip": ip, "reason": reason, "createdAt": _iso(now), "expiresAt": _iso(now + ttl * 60),
                "expiresTs": now + ttl * 60, "ttlMinutes": ttl, "source": source, "alertId": alert_id,
                "backend": self._cfg["backend"], "status": status, "error": None}

    def _do_block(self, ip, reason, ttl, source, alert_id):
        b = self._mk(ip, reason, ttl, source, alert_id, "active")
        prot = self._protected(ip)
        if prot:
            b.update(status="failed", error="refused: " + prot)
            self._log("refuse", ip, source, prot, "refused")
            return b
        now = self.clock()
        self._recent = [t for t in self._recent if now - t < 60]
        # The cap protects real firewalls from a runaway feedback loop; dry-run blocks change nothing,
        # so they never count against it (a demo can show several attacks in a row).
        dry = self._cfg.get("backend", "dry-run") == "dry-run"
        if not dry and len(self._recent) >= self._cfg["maxBlocksPerMinute"]:
            b.update(status="failed", error="rate limit: maxBlocksPerMinute exceeded")
            self._log("refuse", ip, source, "rate limit", "refused")
            self._tell("MAVIS: block rate limit hit; refused %s (%s)" % (ip, reason))
            return b
        ok, err = self._backend.block(ip, b["ttlMinutes"])
        if ok:
            self._recent.append(now)
            self._blocks[ip] = b
            self._pending.pop(ip, None)
            self._save()
            self._log("block", ip, source, reason, "ok")
            self._tell("MAVIS: blocked %s for %sm (%s)" % (ip, b["ttlMinutes"], reason))
        else:
            b.update(status="failed", error=err)
            self._log("block", ip, source, reason, "error: %s" % err)
        return b

    def block(self, ip, reason, ttl_minutes=None, source="analyst", alert_id=None):
        with self._lock:
            return self._do_block(ip, reason, ttl_minutes, source, alert_id)

    def unblock(self, ip, source="analyst"):
        with self._lock:
            had = self._blocks.pop(ip, None)
            self._pending.pop(ip, None)
            ok, err = self._backend.unblock(ip) if had else (True, None)
            self._save()
            self._log("unblock", ip, source, "", ("ok" if ok else "error: %s" % err) if had else "not blocked")
            return {"ip": ip, "unblocked": bool(had), "error": err}

    def blocks(self):
        with self._lock:
            self._prune()
            return [dict(b) for b in self._blocks.values()]

    def pending(self):
        with self._lock:
            return [dict(b) for b in self._pending.values()]

    def approve(self, ip):
        with self._lock:
            p = self._pending.get(ip)
            if not p:
                return None
            return self._do_block(ip, p["reason"], p.get("ttlMinutes"), p["source"], p.get("alertId"))

    def reject(self, ip):
        with self._lock:
            p = self._pending.pop(ip, None)
            self._save()
            self._log("reject", ip, "analyst", (p or {}).get("reason", ""), "ok" if p else "not pending")
            return bool(p)

    def audit(self, limit=200):
        try:
            with open(self.audit_path) as f:
                lines = f.readlines()[-int(limit):]
            return [json.loads(l) for l in lines if l.strip()][::-1]
        except OSError:
            return []
