"""Blocking backends. Each: block(ip, ttl_minutes) / unblock(ip) -> (ok, error|None). Never raise.

pf (macOS) one-time setup:
  1. add to /etc/pf.conf:   table <mavis_block> persist
                            block drop quick from <mavis_block> to any
                            block drop quick from any to <mavis_block>
  2. sudo pfctl -f /etc/pf.conf && sudo pfctl -e
  3. run the server with sudo (pfctl needs root), or use the dry-run backend.
nftables (Linux) setup: nft add table inet mavis; nft add set inet mavis blocklist
  '{ type ipv4_addr; flags timeout; }'; add a chain with 'ip saddr @blocklist drop'.
"""
import json
import os
import subprocess
import urllib.request

TIMEOUT = 10


def _run(cmd, runner=None):
    try:
        p = (runner or subprocess.run)(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        if p.returncode != 0:
            return False, ((p.stderr or p.stdout or "").strip() or "exit %s" % p.returncode)
        return True, None
    except Exception as e:  # noqa: BLE001
        return False, "%s: %s" % (type(e).__name__, e)


class DryRunBackend:
    name = "dry-run"

    def block(self, ip, ttl_minutes):
        return True, None

    def unblock(self, ip):
        return True, None


class PfBackend:
    name = "pf"

    def __init__(self, runner=None, is_root=None):
        self.runner = runner
        self.is_root = is_root if is_root is not None else (lambda: os.geteuid() == 0)

    def _go(self, args):
        if not self.is_root():
            return False, ("pf needs root: run the server with sudo, or switch the backend to dry-run")
        return _run(["pfctl", "-t", "mavis_block", "-T"] + args, self.runner)

    def block(self, ip, ttl_minutes):
        return self._go(["add", ip])

    def unblock(self, ip):
        return self._go(["delete", ip])


class NftBackend:
    name = "nftables"

    def __init__(self, runner=None):
        self.runner = runner

    def block(self, ip, ttl_minutes):
        return _run(["nft", "add", "element", "inet", "mavis", "blocklist",
                     "{ %s timeout %dm }" % (ip, int(ttl_minutes))], self.runner)

    def unblock(self, ip):
        return _run(["nft", "delete", "element", "inet", "mavis", "blocklist", "{ %s }" % ip], self.runner)


class CloudflareBackend:
    name = "cloudflare"

    def __init__(self, opener=None):
        self.opener = opener or urllib.request.urlopen
        self.rule_ids = {}

    def _req(self, method, path, body=None):
        tok, zone = os.environ.get("CLOUDFLARE_API_TOKEN"), os.environ.get("CLOUDFLARE_ZONE_ID")
        if not tok or not zone:
            return None, "set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID"
        url = "https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules%s" % (zone, path)
        req = urllib.request.Request(url, method=method, headers={
            "Authorization": "Bearer " + tok, "Content-Type": "application/json"},
            data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.opener(req, timeout=TIMEOUT) as r:
                d = json.loads(r.read().decode() or "{}")
            if d.get("success") is False:
                return None, str(d.get("errors"))
            return d, None
        except Exception as e:  # noqa: BLE001
            return None, "%s: %s" % (type(e).__name__, e)

    def block(self, ip, ttl_minutes):
        d, err = self._req("POST", "", {"mode": "block", "notes": "MAVIS auto-block",
                                        "configuration": {"target": "ip", "value": ip}})
        if err:
            return False, err
        rid = (d.get("result") or {}).get("id")
        if rid:
            self.rule_ids[ip] = rid
        return True, None

    def unblock(self, ip):
        rid = self.rule_ids.pop(ip, None)
        if not rid:
            return False, "no Cloudflare rule id known for %s" % ip
        err = self._req("DELETE", "/" + rid)[1]
        return err is None, err


def notify_slack(text, opener=None):
    url = os.environ.get("MAVIS_SLACK_WEBHOOK")
    if not url:
        return False
    try:
        req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        (opener or urllib.request.urlopen)(req, timeout=5)
        return True
    except Exception:  # noqa: BLE001
        return False


def make_backend(name):
    return {"dry-run": DryRunBackend, "pf": PfBackend, "nftables": NftBackend,
            "cloudflare": CloudflareBackend}[name]()
