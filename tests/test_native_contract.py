"""Optional integration checks against the two pinned upstream installer snapshots."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import unittest
from urllib.parse import unquote, urlsplit

import node_sync as sync


UPSTREAM = os.environ.get("HY2_VLESS_TEST_UPSTREAM")
NATIVE_LIBRARIES = ("common.sh", "quota-lib.sh", "iplimit-lib.sh", "quota-query.py")


def native_files(base, protocol):
    repository = "hy2jieshu" if protocol == "hy2" else "jieshu"
    installed = {}
    for source in (f"{protocol}.sh", "natjichang.sh"):
        raw = (base / f"{repository}-{source}").read_bytes()
        for match in re.finditer(rb"^[ \t]*cat >([^\n]+?)<<'(\w+)'\n", raw, re.M):
            path = match[1].decode()
            delimiter = match[2]
            end = raw.index(b"\n" + delimiter + b"\n", match.end())
            data = raw[match.end():end + 1]
            candidates = [name for name in sync.NATIVE_SHA256[protocol] if re.search(r"/" + re.escape(name) + r"""['"]?\s*$""", path)]
            if delimiter in (b"CREATOR", b"__NAT_MKTEMP_FINAL__"):
                candidates = [f"{protocol}_mktemp_nat.sh"]
            elif delimiter in (b"PREFLIGHT", b"NAT_PREFLIGHT"):
                candidates = [f"{protocol}_nat_preflight.sh"]
            for name in candidates:
                installed[name] = data
    return installed


FAKE_NFT = r'''
import json
import os
from pathlib import Path
import re
import sys

path = Path(os.environ["HVS_TEST_NFT"])
prefix = os.environ["HVS_TEST_PREFIX"]
state = json.loads(path.read_text())
ports = state["ports"]
args = sys.argv[1:]
if args == ["-j", "list", "tables"]:
    kinds = ["pq", "iplimit"] if state.get("family_guards") else ["pq"]
    print(json.dumps({"nftables": [{"table": {"family": "inet", "name": f"{prefix}_{kind}"}} for kind in kinds]}))
    raise SystemExit(0)
if args == ["-j", "-n", "-a", "list", "table", "inet", "vr_pq"] and state.get("family_guards"):
    table = {"family": "inet", "table": "vr_pq"}
    objects = [{"chain": dict(table, name=f"pq_{direction}")} for direction in ("input", "output")]
    for port, row in ports.items():
        objects.append({"quota": dict(table, name=f"vr_pq_q_{port}", used=row["used"])})
        for direction, used in (("in", row["used"]), ("out", 0)):
            objects.append({"counter": dict(table, name=f"vr_pq_{direction}_{port}", bytes=used)})
            for kind in ("count", "drop"):
                objects.append({"rule": dict(table, chain=f"pq_{direction}put",
                                             comment=f"vr-pq-{kind}-{direction}-{port}")})
    print(json.dumps({"nftables": objects}))
    raise SystemExit(0)

args = [a for a in args if a not in ("-a", "-n")]
if args in (["list", "table", "inet", prefix + "_iplimit"],
            ["list", "chain", "inet", prefix + "_iplimit", "il_input"]):
    for port in state.get("family_guards", []):
        print(f'drop comment "{prefix}-il-family-{port}"')
    raise SystemExit(0)
if args[:2] == ["list", "table"]:
    if args[-1] != prefix + "_pq":
        raise SystemExit(1)
    for port in ports:
        print(f'comment "{prefix}-pq-drop-in-{port}"')
    raise SystemExit(0)
if args[:2] == ["list", "chain"]:
    direction = "in" if args[-1] == "pq_input" else "out"
    for idx, (port, row) in enumerate(ports.items(), start=1):
        print(f'drop comment "{prefix}-pq-drop-{direction}-{port}" # handle {idx*10}')
        if row["limit"]:
            print(f'counter comment "{prefix}-pq-count-{direction}-{port}" # handle {idx*10+1}')
    raise SystemExit(0)
if args[:2] in (["list", "quota"], ["list", "counter"]):
    name = args[-1]
    row = ports.get(name.split("_")[-1])
    if not row or not row["limit"]:
        raise SystemExit(1)
    if args[1] == "quota":
        print(f"over {row['limit']} bytes used {row['used']} bytes")
    else:
        print(f"packets 1 bytes {row['used'] if '_in_' in name else 0}")
    raise SystemExit(0)
if args[:1] == ["-f"]:
    rules = Path(args[1]).read_text()
    match = re.search(r"(?:dport|sport) (\d+)", rules)
    amount = re.search(r"\bover (\d+) bytes", rules)
    if match:
        port = match[1]
        if state.get("fail_once") == port and amount:
            del state["fail_once"]
            path.write_text(json.dumps(state))
            raise SystemExit(1)
        ports[port] = {"limit": int(amount[1]) if amount else 0, "used": 0}
    else:
        handles = {int(n) // 10 for n in re.findall(r"handle (\d+)", rules)}
        for idx, port in enumerate(list(ports), start=1):
            if idx in handles:
                del ports[port]
    path.write_text(json.dumps(state))
    raise SystemExit(0)
raise SystemExit(1)
'''


class FixtureHost(sync.Native):
    def __init__(self, protocol, root, reference):
        super().__init__(protocol)
        self.root = root
        self.lib = root / "lib"
        self.sbin = root / "bin"
        self.state = root / "state"
        self.units = root / "units"
        self.config = root / "config"
        self.runtime = root / "run"
        self.pending = self.state / ".hy2-vless-sync-recovery.json"
        self.kernel = root / "kernel.json"
        self.capabilities = {}
        self.kernel.write_text('{"ports":{}}')
        for path in (self.lib, self.sbin, self.units, self.config, self.runtime,
                     *(self.state / path for path in ("main", "temp", "quota", "iplimit"))):
            path.mkdir(parents=True, exist_ok=True)
        for name in ("temp.lock", self.quota_lock, "iplimit.lock"):
            (self.runtime / name).touch()
        (self.state / "main/main.env").write_text(f"{self.main_key}=443\n")
        replacements = (
            (f"/usr/local/lib/{self.directory}", self.lib), (f"/var/lib/{self.directory}", self.state),
            (f"/run/{self.directory}", self.runtime), ("/etc/systemd/system", self.units),
            ("/etc/hysteria/temp", self.config), ("/etc/hysteria", self.root / "hy2-etc"),
            ("/usr/local/etc/xray", self.config), ("/var/log/hy2", self.root / "logs"),
            ("/usr/local/sbin", self.sbin),
        )
        for name, raw in reference.items():
            data = raw.decode()
            for old, new in replacements:
                data = data.replace(old, str(new))
            if protocol == "hy2" and name == "common.sh":
                data = data.replace('HY2_TEMP_CFG_DIR="$' + '{HY2_ETC_DIR}/temp"',
                                    f'HY2_TEMP_CFG_DIR="{self.config}"')
            folder = self.lib if name in NATIVE_LIBRARIES else self.sbin
            place = folder / name
            place.write_text(data)
            place.chmod(0o755)
            self.capabilities[name] = sync.digest(place.read_bytes())
        # Mock unrelated aggregate publishing and systemd/socket APIs. The actual
        # native quota writer, reset, creator hook and delete code still run.
        self.executable(f"{protocol}_temp_sub.sh", "#!/bin/bash\nexit 0\n")
        self.executable("systemctl", '#!/bin/bash\n[[ "$1" != is-active ]] && exit 0\nprintf "inactive\\n"\nexit 3\n')
        self.executable("ss", "#!/bin/bash\nexit 0\n")
        self.executable("nft", "#!/usr/bin/env python3\n" + FAKE_NFT)

    def executable(self, name, text):
        file = self.sbin / name
        file.write_text(text)
        file.chmod(0o755)

    def env(self, **extra):
        env = super().env(**extra)
        env["PATH"] = str(self.sbin) + ":" + os.environ["PATH"]
        env["HVS_TEST_NFT"] = str(self.kernel)
        env["HVS_TEST_PREFIX"] = self.prefix
        return env

    def node_files(self, row, meta):
        row["unit_hash"] = "fixture-systemd"

    def put_node(self, port, *, quota=260, left=180, used=0, auto=False, due=False):
        tag = f"{self.tag_prefix}user-{port}"
        start = int(time.time()) - 1000
        expiry = start + 5000000
        creds = {"PASSWORD": "fixture-only"} if self.protocol == "hy2" else {"UUID": "fixture-only"}
        raw = dict(TAG=tag, PORT=port, CREATE_EPOCH=start, EXPIRE_EPOCH=expiry, DURATION_SECONDS=5000000,
                   IP_LIMIT=0, IP_STICKY_SECONDS=200, IP_VERSION=4, PQ_LIMIT_BYTES=quota, **creds)
        for path in self.paths(tag):
            path.write_text("fixture")
        self.paths(tag)[0].write_text("".join(f"{k}={v}\n" for k, v in raw.items()))
        q = dict(total=quota, period=2592000 if auto else 0, next=(start - 3 if due else start + 2592000) if auto else 0,
                 created=start, last=0, duration=5000000 if auto else 0, expires=expiry if auto else 0)
        row, meta = self.read_tag(tag)
        row["unit_hash"] = "fixture-systemd"
        with self.locked(), self.quota_locked():
            self.quota_write(row, q, left + used)
            kernel = json.loads(self.kernel.read_text())
            kernel["ports"][str(port)]["used"] = used
            self.kernel.write_text(json.dumps(kernel))
            row["quota"] = self.quota(row, meta)
        return row


class CreatorFixture(FixtureHost):
    """Use the original creator body with simulated host, service and DNS APIs."""
    def __init__(self, protocol, root, reference):
        super().__init__(protocol, root, reference)
        self.reference = reference
        self.wg_dir = root / "wireguard"
        self.live = root / "active-services"
        self.subscription = root / f"{protocol}_temp_subscription.txt"
        self.wg_dir.mkdir()
        self.live.mkdir()
        (self.wg_dir / "wg-test.env").write_text("MARK=2333\nTABLE_ID=125\nRULE_PRIORITY=31000\n")
        (self.live / "wg-quick@wg-test.service").touch()
        (self.live / "pq-reset.timer").touch()
        for name in ("cert", "key"):
            (self.root / name).write_text("fixture\n")

        self.executable("systemctl", r'''#!/bin/bash
set -eu
action=$1
unit=${@: -1}
case "$action" in
  is-active) if [[ -f "$HVS_TEST_LIVE/$unit" ]]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
  start) if [[ "$unit" == *-temp-* && "$HVS_TEST_FAIL" == 1 ]]; then exit 1; fi; touch "$HVS_TEST_LIVE/$unit" ;;
  stop|kill) rm -f -- "$HVS_TEST_LIVE/$unit" ;;
esac
''')
        self.executable("systemd-analyze", "#!/bin/bash\nexit 0\n")
        self.executable("hysteria", "#!/bin/bash\nexit 0\n")
        self.executable("xray", "#!/bin/bash\nprintf 'a1234567-1234-1234-1234-a123456789ab\\n'\n")
        self.executable("getent", "#!/bin/bash\nprintf '192.0.2.1 STREAM fixture\\n'\n")
        self.executable("stat", "#!/bin/bash\n[[ \"$1 $2\" == '-c %u' ]] && { echo 0; exit; }; exec /usr/bin/stat \"$@\"\n")
        self.executable("ip", "#!/bin/bash\n[[ \"$*\" == *route* ]] && echo '1.1.1.1 dev wg-test'; exit 0\n")
        self.executable("wg", "#!/bin/bash\nprintf 'peer\\t%s\\n' \"$(date +%s)\"\n")
        for name in ("wg_nat_healthcheck.sh", "wg_nat_guard.sh", f"{protocol}_audit.sh"):
            self.executable(name, "#!/bin/bash\nexit 0\n")
        self.executable(f"{protocol}_temp_sub.sh", r'''#!/bin/bash
shopt -s nullglob
files=("$HVS_TEST_STATE"/temp/*.url)
: >"$HVS_TEST_SUB"
if (("${#files[@]}")); then cat "${files[@]}" >"$HVS_TEST_SUB"; fi
''')

        # External environment overrides only. Config and metadata generation,
        # quota calculation, runtime lifecycle order and rollback are upstream.
        prefix = self.prefix
        common = self.lib / "common.sh"
        conf = r'''
fixture_listener() {
  local path tag
  for path in "$HVS_TEST_STATE"/temp/*.env; do
    [[ -f "$path" ]] || continue
    tag=${path##*/}
    if [[ -f "$HVS_TEST_LIVE/${tag%.env}.service" ]] && grep -Fxq "PORT=$1" "$path"; then
      return 0
    fi
  done
  return 1
}
'''
        conf += f'''
{prefix}_require_root_supported_os() {{ :; }}
{prefix}_wait_unit_and_port() {{ systemctl is-active --quiet "$1"; }}
{prefix}_wait_unit_and_udp_port() {{ systemctl is-active --quiet "$1"; }}
'''
        if protocol == "hy2":
            conf += '''
hy2_load_defaults() {
  HY_DOMAIN=fixture.invalid
  HY_IPV6_DOMAIN=v6.fixture.invalid
  MASQ_URL=https://fixture.invalid/
  ENABLE_SALAMANDER=0
  SALAMANDER_PASSWORD=
}
hy2_port_is_listening_udp() { fixture_listener "$1"; }
hy2_main_cert_paths() { printf '%s\\n' "$HVS_TEST_ROOT/cert" "$HVS_TEST_ROOT/key"; }
hy2_get_public_ipv4_candidates() { printf '192.0.2.2\\n'; }
hy2_get_public_ipv6_candidates() { printf '2001:db8::2\\n'; }
hy2_require_domain_points_here() { :; }
hy2_validate_server_addr() { :; }
'''
        else:
            conf += '''
vr_read_main_reality() { printf '%s\\n' fixture-private fixture.invalid:443 fixture.invalid 443; }
vr_load_defaults() { PUBLIC_DOMAIN=fixture.invalid; PUBLIC_IPV6_DOMAIN=v6.fixture.invalid; }
vr_main_url_published_pbk() { printf 'abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOP\\n'; }
vr_port_is_listening() { fixture_listener "$1"; }
vr_test_xray_config() { :; }
vr_get_public_ipv6_candidates() { printf '2001:db8::2\\n'; }
vr_require_domain_aaaa_points_here() { :; }
'''
        common.write_text(common.read_text() + conf)
        ip_lib = self.lib / "iplimit-lib.sh"
        ip_lib.write_text(ip_lib.read_text() + f'''
{prefix}_il_apply_family_guard() {{ :; }}
{prefix}_il_family_guard_state() {{ echo active; }}
{prefix}_il_state() {{ echo active; }}
{prefix}_il_add_managed_port() {{ {prefix}_il_write_meta "$1" "$4" "$5" "$2" "$3" "$6"; }}
''')
        # The same native cleanup script uses lock and port guards against the
        # relocated native tree. Keep its approved hash for this fixture.
        cleanup = self.sbin / f"{protocol}_cleanup_one.sh"
        data = self.substitute(cleanup.read_text())
        cleanup.write_text(data)
        self.capabilities[cleanup.name] = sync.digest(cleanup.read_bytes())
        self.fail_start = False

    def substitute(self, script):
        replacements = (
            (f"/usr/local/lib/{self.directory}", self.lib), (f"/var/lib/{self.directory}", self.state),
            (f"/run/{self.directory}", self.runtime), ("/usr/local/sbin", self.sbin),
            ("/etc/systemd/system", self.units), ("/etc/wireguard", self.wg_dir),
            ("/run/hy2-wg", self.root / "wg-lock"), ("/usr/local/bin/xray", self.sbin / "xray"),
            (f"/root/{self.protocol}_temp_subscription.txt", self.subscription),
            ("/var/lib/portbw", self.root / "portbw"),
        )
        for old, new in replacements:
            script = script.replace(old, str(new))
        return script

    def env(self, **extra):
        env = super().env(**extra)
        env.update(HVS_TEST_FAIL=str(int(self.fail_start)), HVS_TEST_LIVE=str(self.live),
                   HVS_TEST_STATE=str(self.state), HVS_TEST_SUB=str(self.subscription), HVS_TEST_ROOT=str(self.root))
        return env

    def prepare_create(self, row):
        options = dict(LANDING=row["landing"]) if self.protocol == "hy2" else {}
        mode = row["landing"]
        if mode == "nat":
            options.update(self.wg_settings(row["wg"], row["handshake"]))
        nat = "_nat" if self.protocol == "vless" and mode == "nat" else ""
        name = f"{self.protocol}_mktemp{nat}.sh"
        script = sync.creator_program(self.reference[name].decode(), self.prefix)
        return name, self.substitute(script), options


@unittest.skipUnless(UPSTREAM and os.name == "posix", "需要本地已固定的原生安装器副本和 Bash")
class NativeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.refs = {proto: native_files(Path(UPSTREAM), proto) for proto in sync.PROTOCOLS}

    def host(self, protocol):
        directory = tempfile.TemporaryDirectory(dir=os.environ.get("HY2_VLESS_TEST_TMP"))
        self.addCleanup(directory.cleanup)
        return FixtureHost(protocol, Path(directory.name), self.refs[protocol])

    def test_native_profiles_and_in_memory_scripts(self):
        for protocol, native in self.refs.items():
            with self.subTest(protocol=protocol):
                self.assertEqual(set(native), set(sync.NATIVE_SHA256[protocol]))
                self.assertEqual({name: hashlib.sha256(raw).hexdigest() for name, raw in native.items()},
                                 sync.NATIVE_SHA256[protocol])
                directory, prefix, _, _ = sync.PROTOCOLS[protocol]
                original = native[f"{protocol}_audit.sh"].decode()
                audits = [sync.audit_program(original, protocol, prefix, directory, source_only=source)
                          for source in (False, True)]
                self.assertTrue(all("mktemp" not in audit for audit in audits))
                names = [f"{protocol}_mktemp.sh"]
                if protocol == "vless":
                    names.append("vless_mktemp_nat.sh")
                scripts = audits + [sync.creator_program(native[name].decode(), prefix) for name in names]
                for script in scripts:
                    test = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
                    self.assertEqual(test.returncode, 0, test.stderr)

    def test_empty_native_audit_and_missing_metadata_are_distinct(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                name = f"{proto}_temp_sub.sh"
                host.capabilities[name] = sync.digest((host.sbin / name).read_bytes())
                host.executable("systemctl", "#!/bin/bash\nprintf 'active\\n'\n")
                host.executable("ss", "#!/bin/bash\nif [[ \"$*\" == *-lntu* ]]; then "
                                "echo 'tcp LISTEN 0 128 127.0.0.1:443 0.0.0.0:*'; else "
                                "echo 'LISTEN 0 128 127.0.0.1:443 0.0.0.0:*'; fi\n")
                original_checked, original_bash = host.checked, host.bash
                host.checked = lambda name: self.refs[proto][name].decode() if name.endswith("_audit.sh") else original_checked(name)
                host.bash = lambda text, **kwargs: original_bash(
                    text.replace(f"/usr/local/lib/{host.directory}", str(host.lib)), **kwargs)
                before = {p.relative_to(host.root) for p in host.root.rglob("*")}
                with host.locked():
                    valid = host.inventory()
                self.assertFalse(valid["issues"], valid["issues"])
                self.assertEqual(valid["nodes"], [])
                self.assertEqual(before, {p.relative_to(host.root) for p in host.root.rglob("*")})
                (host.config / (host.tag_prefix + "missing" + host.config_extension)).write_text("fixture")
                with host.locked():
                    invalid = host.inventory()
                self.assertTrue(any("清单不完整" in msg for msg in invalid["issues"]))

    def test_source_reads_live_node_without_opening_native_locks_for_writing(self):
        for protocol in sync.PROTOCOLS:
            with self.subTest(protocol=protocol):
                self.check_read_only_source(protocol)

    def check_read_only_source(self, protocol):
        import fcntl
        from contextlib import ExitStack

        host = self.host(protocol)
        row = host.put_node(40002, quota=200, left=90, used=11, auto=True)
        kernel = json.loads(host.kernel.read_text())
        kernel["family_guards"] = [row["port"]]
        host.kernel.write_text(json.dumps(kernel))
        tag, port = row["tag"], row["port"]
        _, config, unit, url = host.paths(tag)
        if protocol == "hy2":
            config.write_text(f"listen: 127.0.0.1:{port}\n")
        else:
            config.write_text(json.dumps({"inbounds": [{"port": port, "protocol": protocol}]}))
        unit.write_text(f"[Service]\nExecStart={host.sbin / (protocol + '_run_temp.sh')} {tag} {config}\n"
                        f"ExecStopPost={host.sbin / (protocol + '_cleanup_one.sh')} {tag} --from-stop-post\n")
        url.write_text(f"{protocol}://fixture\n")
        subscription = host.root / f"{protocol}_temp_subscription.txt"
        subscription.write_text(url.read_text())
        name = f"{protocol}_temp_sub.sh"
        host.capabilities[name] = sync.digest((host.sbin / name).read_bytes())
        pid = os.getpid()
        cgroup = Path(f"/proc/{pid}/cgroup").read_text().splitlines()[0].split(":", 2)[-1]
        host.node_files = sync.Native.node_files.__get__(host)
        host.executable("systemctl", f'''#!/bin/bash
if [[ "$1" == show ]]; then
    cat <<'OUT'
FragmentPath={unit}
DropInPaths=
MainPID={pid}
ActiveState=active
ControlGroup={cgroup}
OUT
else
    printf 'active\n'
fi
''')
        transport = "udp" if protocol == "hy2" else "tcp"
        host.executable("ss", f'''#!/bin/bash
if [[ "$*" == *-lntu* ]]; then
    printf '{transport} '
elif [[ "$*" == *-lunp* || "$*" == *-ltnp* ]]; then
    printf 'LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:* users:(("fixture",pid={pid},fd=3))\n'
    exit 0
fi
printf 'LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*\n'
if [[ "$*" != *-lntu* ]]; then
    printf 'LISTEN 0 128 127.0.0.1:443 0.0.0.0:*\n'
fi
''')
        checked, bash = host.checked, host.bash
        audit_name = f"{protocol}_audit.sh"
        host.checked = lambda name: self.refs[protocol][name].decode() if name == audit_name else checked(name)
        host.bash = lambda script, **kwargs: bash(
            script.replace(f"/usr/local/lib/{host.directory}", str(host.lib)).replace(
                f"/root/{subscription.name}", str(subscription)), **kwargs)
        host.role = "source"
        paths = [host.runtime / name for name in ("temp.lock", host.quota_lock, "iplimit.lock")]
        for path in paths:
            path.unlink()

        def check_inventory(wanted):
            snapshot = host.inventory()
            self.assertFalse(snapshot["issues"], snapshot["issues"])
            self.assertEqual([node["port"] for node in snapshot["nodes"]], [port])
            self.assertEqual(snapshot["nodes"][0]["quota"]["left"], wanted)
            live = host.one(snapshot["nodes"][0])
            self.assertEqual(live["quota"]["left"], wanted)
            self.assertEqual(sync.schedule(live["quota"]), sync.schedule(row["quota"]))
            self.assertIsInstance(snapshot["source_revision"], str)
            return snapshot["source_revision"]

        revision = check_inventory(90)
        self.assertFalse(any(path.exists() for path in paths))

        kernel["ports"][str(port)]["used"] += 2
        host.kernel.write_text(json.dumps(kernel))
        with ExitStack() as locks:
            for path in paths:
                path.write_text("native lock marker")
                lock = locks.enter_context(path.open("rb"))
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = [(path.stat().st_mtime_ns, path.stat().st_ctime_ns) for path in paths]
            self.assertEqual(check_inventory(88), revision)
            self.assertIsInstance(host.absent(port + 1, revision), int)
            with self.assertRaisesRegex(sync.SyncError, "来源已出现端口"):
                host.absent(port, revision)
            self.assertEqual([(path.stat().st_mtime_ns, path.stat().st_ctime_ns) for path in paths], before)
            self.assertTrue(all(path.read_text() == "native lock marker" for path in paths))

        url.write_text(f"{protocol}://changed\n")
        with self.assertRaisesRegex(sync.SyncError, "来源节点清单在删除前变化"):
            host.absent(port + 1, revision)

    def test_real_quota_helpers_read_exact_live_balance_and_keep_plan(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                row = host.put_node(40002, quota=200, left=90, used=11, auto=True)
                before = sync.schedule(row["quota"])
                ref = copy.deepcopy(row)
                ref["quota"]["left"] = 76
                ref["sampled_at"] = int(time.time())
                with host.locked():
                    result = host.balance(row, ref, "fixture-source")
                    updated = host.one(row)
                self.assertEqual(result["before"], 90)
                self.assertEqual(updated["quota"]["left"], 76)
                self.assertEqual(sync.schedule(updated["quota"]), before)
                self.assertFalse(host.pending.exists())

    def test_real_quota_helpers_preserve_or_execute_reset(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                cyclical = host.put_node(40002, quota=200, left=90, auto=True, due=True)
                no_reset = host.put_node(40003, quota=180, left=77)
                with host.locked(), host.quota_locked():
                    for row in (cyclical, no_reset):
                        host.call(sync.RECOVER_QUOTA, "quota-lib.sh", row["port"], "reset", 0, quota_lock=True)
                    row, meta = host.read_tag(cyclical["tag"])
                    reset = host.quota(row, meta)
                    row, meta = host.read_tag(no_reset["tag"])
                    off = host.quota(row, meta)
                self.assertEqual(reset["left"], 200)
                self.assertEqual(reset["total"], 200)
                self.assertGreater(reset["next"], int(time.time()))
                self.assertEqual((off["period"], off["next"], off["left"]), (0, 0, 77))

    def test_real_creator_hook_preserves_zero_bytes_and_old_anchor(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                row = host.put_node(40002, quota=201, left=80, auto=True)
                native = self.refs[proto][f"{proto}_mktemp.sh"].decode()
                hook = sync.creator_program(native, host.prefix).split("#!/usr/bin/env bash", 1)[0]
                args = (row["port"], 201, "temp", row["tag"], row["duration"], row["expires"])
                body = f"set -euo pipefail\nsource {shlex.quote(str(host.lib / 'quota-lib.sh'))}\n" + hook
                body += "\nhvs_initial_quota " + " ".join(shlex.quote(str(arg)) for arg in args) + "\n"
                q = row["quota"]
                options = dict(HVS_TOTAL="201", HVS_LEFT="0", HVS_EXPIRES=str(row["expires"]),
                               HVS_QDURATION=str(q["duration"]), HVS_QEXPIRES=str(q["expires"]),
                               HVS_NEXT=str(q["next"]), HVS_PERIOD=str(q["period"]), HVS_QCREATED=str(q["created"]),
                               HVS_QLAST=str(q["last"]))
                with host.locked():
                    host.bash(body, env=host.env(**options))
                    read = host.one(row)
                self.assertEqual(read["quota"]["left"], 0)
                self.assertEqual(sync.schedule(read["quota"]), sync.schedule(row["quota"]))

    def test_real_native_delete_keeps_other_ports(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                victim = host.put_node(40005)
                survivor = host.put_node(40006)
                with host.locked():
                    status = host.delete(victim, "fixture-source", int(time.time()))
                    read = host.one(survivor)
                    self.assertTrue(host.tag_absent(40005, victim["tag"]))
                self.assertEqual(status["action"], "delete")
                self.assertEqual(read["quota"]["left"], survivor["quota"]["left"])
                self.assertFalse(host.pending.exists())
                self.assertEqual(set(p.name for p in host.runtime.iterdir()),
                                 {"temp.lock", host.quota_lock, "iplimit.lock"})

    def test_real_quota_failure_rolls_back_before_any_next_action(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                row = host.put_node(40002, left=95, used=7)
                kernel = json.loads(host.kernel.read_text())
                kernel["fail_once"] = "40002"
                host.kernel.write_text(json.dumps(kernel))
                ref = copy.deepcopy(row)
                ref["quota"]["left"] = 64
                ref["sampled_at"] = int(time.time())
                with host.locked():
                    with self.assertRaisesRegex(sync.SyncError, "已恢复原余额"):
                        host.balance(row, ref, "fixture-source")
                    current = host.one(row)
                self.assertEqual(current["quota"]["left"], 95)
                self.assertFalse(host.pending.exists())

    def test_recovery_clears_a_verified_native_pending_balance(self):
        for proto in sync.PROTOCOLS:
            with self.subTest(proto=proto):
                host = self.host(proto)
                row = host.put_node(40002, left=95)
                meta_path = host.state / "quota/40002.env"
                data = meta_path.read_text().replace("REBUILD_PENDING=0", "REBUILD_PENDING=1")
                meta_path.write_text(data)
                record = dict(version=sync.WIRE_VERSION, host=host.host, protocol=proto, action="balance",
                              source="fixture-source", port=40002, tag=row["tag"], generation=row["generation"],
                              before=sync.schedule(row["quota"]), old_left=95, wanted=40)
                with host.locked():
                    host.store_recovery(record)
                    host.recover(record, {"host": "fixture-source"})
                    current = host.one(row)
                self.assertEqual(current["quota"]["left"], 95)
                self.assertNotIn("REBUILD_PENDING=1", meta_path.read_text())
                self.assertFalse(host.pending.exists())


    def test_full_native_creators_use_the_selected_port_and_absolute_plan(self):
        for protocol, mode in ((p, m) for p in sync.PROTOCOLS for m in ("local", "nat")):
            with self.subTest(protocol=protocol, mode=mode):
                fixture = tempfile.TemporaryDirectory(dir=os.environ.get("HY2_VLESS_TEST_TMP"))
                self.addCleanup(fixture.cleanup)
                host = CreatorFixture(protocol, Path(fixture.name), self.refs[protocol])
                source = self.host(protocol).put_node(40011, quota=201, left=0, auto=True)
                source.update(landing=mode, wg="wg-test", handshake=180, ip_limit=3, sampled_at=int(time.time()))
                with host.locked():
                    result = host.create(source, "fixture-source")
                self.assertEqual(result["port"], 40011)
                self.assertEqual(result["expires"], source["expires"])
                self.assertEqual(result["landing"], mode)
                tag = result["tag"]
                self.assertRegex(tag, rf"^{protocol}-temp-sync-{mode}-40011-[0-9a-f]{{10}}$")
                link = host.paths(tag)[3].read_text().strip()
                name = unquote(urlsplit(link).fragment)
                expected_name = tag.replace("hy2-temp-", "hy2-nat-", 1) if protocol == "hy2" and mode == "nat" else tag
                self.assertEqual(name, expected_name)
                self.assertEqual(result["quota"]["left"], 0)
                self.assertEqual(sync.schedule(result["quota"]), sync.schedule(source["quota"]))
                self.assertIn("cat -- ", result["link_command"])
                self.assertFalse(host.pending.exists())

    def test_native_creator_start_failure_leaves_no_port_or_journal(self):
        for protocol in sync.PROTOCOLS:
            with self.subTest(protocol=protocol):
                fixture = tempfile.TemporaryDirectory(dir=os.environ.get("HY2_VLESS_TEST_TMP"))
                self.addCleanup(fixture.cleanup)
                host = CreatorFixture(protocol, Path(fixture.name), self.refs[protocol])
                source = self.host(protocol).put_node(40011, quota=201, left=80, auto=True)
                source["sampled_at"] = int(time.time())
                host.fail_start = True
                with host.locked():
                    with self.assertRaisesRegex(sync.SyncError, "已清除本次节点"):
                        host.create(source, "fixture-source")
                self.assertFalse(tuple((host.state / "temp").iterdir()))
                self.assertFalse(tuple((host.state / "quota").iterdir()))
                self.assertFalse(tuple(host.config.iterdir()))
                self.assertFalse(tuple(host.units.iterdir()))
                self.assertFalse(host.pending.exists())
