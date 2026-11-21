import contextlib
import copy
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import node_sync as sync


NOW = int(time.time())


def node(protocol, port, tag, left=None, total=200, *, reset=0, nat=False):
    quantum = None if left is None else dict(
        total=total, left=left, stored=left, period=2592000 if reset else 0,
        next=reset, created=NOW - 60, last=0, duration=5000000 if reset else 0,
        expires=NOW + 4999940 if reset else 0,
    )
    return dict(port=port, tag=f"{protocol}-temp-{tag}", generation=f"gen-{protocol}-{tag}",
                unit_hash=f"cfg-{protocol}-{tag}", created=NOW - 60, expires=NOW + 4999940,
                duration=5000000, landing="nat" if nat else "local", family="6" if nat else "4",
                ip_limit=3, sticky=150, wg="wg-east" if nat else None, handshake=180 if nat else None,
                quota=quantum)


def inventory(protocol, *nodes):
    return dict(protocol=protocol, host=f"host-{protocol}", boot=f"boot-{protocol}", main=443,
                nodes=list(nodes), issues=[], reserved=[443, *(x["port"] for x in nodes)],
                reset_timer=True, sampled=NOW, source_revision="fixture-revision")


class Peer:
    def __init__(self, data, changes):
        self.data = data
        self.ident = {key: data[key] for key in ("host", "boot")}
        self.changes = changes
        self.fail_kind = None
        self.late_balance = {}
        self.after_lock = None
        self.prepare_error = None

    def rpc(self, op, **args):
        if op == "inventory":
            return copy.deepcopy(self.data)
        if op == "prepare":
            return [{"port": r["port"], "error": self.prepare_error} for r in args["rows"]] if self.prepare_error else []
        if op == "lock":
            self.changes.append(("lock", self.ident["host"]))
            if self.after_lock:
                self.after_lock()
            return
        if op == "one":
            row = copy.deepcopy(sync.port_map(self.data)[args["row"]["port"]])
            if row["port"] in self.late_balance:
                row["quota"]["left"] = self.late_balance[row["port"]]
            row["sampled_at"] = NOW
            return row
        if op == "absent":
            if args["revision"] != self.data["source_revision"]:
                raise sync.SyncError("source revision changed")
            if args["port"] in sync.port_map(self.data):
                raise sync.SyncError("source port appeared")
            return NOW
        if op in ("create", "balance", "delete"):
            row = args.get("target", args.get("source"))
            port = row["port"]
            self.changes.append((op, port))
            if self.fail_kind == op:
                raise sync.SyncError("test fault")
            if op == "create":
                new = copy.deepcopy(row)
                new["tag"] = f"{self.data['protocol']}-temp-new-{port}"
                new["unit_hash"] = f"new-{port}"
                new["generation"] = f"new-generation-{port}"
                self.data["nodes"].append(new)
                return dict(action=op, port=port, tag=new["tag"], expires=row["expires"], quota=new["quota"],
                            link_command=f"cat -- /controlled/{port}.url")
            if op == "delete":
                if args["sampled_at"] != NOW:
                    raise AssertionError("target deletion did not receive a fresh source sample")
                self.data["nodes"] = [r for r in self.data["nodes"] if r["port"] != port]
                return dict(action=op, port=port)
            quota = sync.port_map(self.data)[port]["quota"]
            left = args["source"]["quota"]["left"]
            old = quota["left"]
            if old == left:
                return dict(action="skip", port=port, message="实时余额已对齐")
            quota.update(left=left, stored=left)
            return dict(action=op, port=port, before=old, wanted=left, actual=left)
        raise AssertionError(op)


def pair(direction):
    other = "hy2" if direction == "vless" else "vless"
    src = inventory(direction, node(direction, 40002, "different", 60, 200),
                    node(direction, 40011, "new-nat", 0, 120, reset=NOW + 80000, nat=True),
                    node(direction, 40013, "unlimited"), node(direction, 40019, "new-open"))
    dst = inventory(other, node(other, 40002, "own-label", 95, 100, reset=NOW + 90000),
                    node(other, 40005, "obsolete", 70), node(other, 40013, "also-unlimited"))
    changes = []
    return Peer(src, changes), Peer(dst, changes), changes


class PlanTests(unittest.TestCase):
    def run_case(self, a, b, **args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = sync.synchronize(a, b, **args)
        return result, output.getvalue() + errors.getvalue()

    def test_only_ports_match_and_default_is_read_only(self):
        a, b, changes = pair("hy2")
        b.data["nodes"][1]["tag"] = a.data["nodes"][1]["tag"]
        result, lines = self.run_case(a, b)
        self.assertEqual(result, 0)
        self.assertFalse(changes)
        for token in ("相同端口（2） 40002, 40013", "待创建（2） 40011, 40019", "待删除（1） 40005"):
            self.assertIn(token, lines)

    def test_both_directions_create_delete_and_keep_target_cycle(self):
        for origin in ("hy2", "vless"):
            with self.subTest(origin=origin):
                a, b, events = pair(origin)
                original = sync.schedule(b.data["nodes"][0]["quota"])
                a.late_balance[40002] = 51
                tokens = iter(("APPLY", "DELETE 1"))
                result, lines = self.run_case(a, b, apply=True, ask=lambda _: next(tokens),
                                              wg_map={"wg-east": "wg-target"})
                self.assertEqual(result, 0, lines)
                self.assertEqual(set(sync.port_map(a.data)), set(sync.port_map(b.data)))
                self.assertEqual(events, [("lock", b.ident["host"]), ("create", 40011), ("create", 40019),
                                          ("balance", 40002), ("delete", 40005)])
                current = sync.port_map(b.data)
                self.assertEqual(current[40002]["quota"]["left"], 51)
                self.assertEqual(sync.schedule(current[40002]["quota"]), original)
                self.assertEqual(current[40011]["ip_limit"], 3)
                self.assertEqual(current[40011]["target_wg"], "wg-target")
                self.assertEqual(current[40011]["quota"]["left"], 0)
                self.assertIsNone(current[40019]["quota"])
                self.assertIn("来源余额已变化", lines)
                self.assertIn("同步完成", lines)

    def test_delete_needs_a_separate_confirmation_even_if_source_empty(self):
        a, b, changes = pair("hy2")
        a.data["nodes"] = []
        answers = iter(("APPLY", "DELETE 2"))
        with self.assertRaisesRegex(sync.SyncError, "已取消删除"):
            self.run_case(a, b, apply=True, ask=lambda _: next(answers))
        self.assertEqual(changes, [])

    def test_incomplete_source_cannot_be_interpreted_as_refunds(self):
        a, b, changes = pair("vless")
        a.data["nodes"] = []
        a.data["issues"] = ["元数据读取失败"]
        result, lines = self.run_case(a, b, apply=True, ask=lambda _: self.fail("asked despite issue"))
        self.assertEqual(result, 1)
        self.assertIn("预检存在冲突", lines)
        self.assertEqual(changes, [])

    def test_cap_conflict_blocks_the_entire_batch(self):
        a, b, changes = pair("hy2")
        a.data["nodes"][0]["quota"]["left"] = 101
        result, lines = self.run_case(a, b, apply=True, ask=lambda _: self.fail("unsafe batch"))
        self.assertEqual(result, 1)
        self.assertIn("超过目标原始总额", lines)
        self.assertEqual(changes, [])

    def test_cap_presence_mismatch_and_main_port_are_conflicts(self):
        a, b, _ = pair("vless")
        a.data["nodes"][0]["quota"] = None
        b.data["main"] = 40011
        result, lines = self.run_case(a, b)
        self.assertEqual(result, 1)
        self.assertIn("一端无配额", lines)
        self.assertIn("受保护主服务端口", lines)

    def test_creation_preflight_reports_unsupported_native_configuration(self):
        a, b, changes = pair("hy2")
        b.prepare_error = "缺少目标 IPv6 发布域名"
        result, lines = self.run_case(a, b, apply=True, ask=lambda _: self.fail("unsupported create"))
        self.assertEqual(result, 1)
        self.assertIn("无法用目标原生创建器转换", lines)
        self.assertFalse(changes)

    def test_stale_approval_is_rejected_before_first_write(self):
        a, b, events = pair("hy2")
        b.after_lock = lambda: b.data["nodes"].append(node("vless", 40071, "new-during-confirm"))
        answers = iter(("APPLY", "DELETE 1"))
        with self.assertRaisesRegex(sync.SyncError, "确认后"):
            self.run_case(a, b, apply=True, ask=lambda _: next(answers))
        self.assertEqual(events, [("lock", b.ident["host"])])

    def test_failed_creation_stops_the_rest_including_deletes(self):
        a, b, events = pair("vless")
        b.fail_kind = "create"
        answers = iter(("APPLY", "DELETE 1"))
        result, lines = self.run_case(a, b, apply=True, ask=lambda _: next(answers))
        self.assertEqual(result, 1)
        self.assertEqual(events, [("lock", b.ident["host"]), ("create", 40011)])
        self.assertIn("失败  40011", lines)
        self.assertIn("未执行  40005", lines)

    def test_source_revision_change_stops_deletes_even_when_port_set_is_unchanged(self):
        a, b, events = pair("vless")
        original_ports = set(sync.port_map(a.data))
        target_rpc = b.rpc

        def change_source_after_balance(op, **args):
            result = target_rpc(op, **args)
            if op == "balance":
                a.data["source_revision"] = "changed-source-revision"
            return result

        b.rpc = change_source_after_balance
        answers = iter(("APPLY", "DELETE 1"))
        result, lines = self.run_case(a, b, apply=True, ask=lambda _: next(answers))
        self.assertEqual(result, 1, lines)
        self.assertEqual(events, [("lock", b.ident["host"]), ("create", 40011), ("create", 40019),
                                  ("balance", 40002)])
        self.assertEqual(set(sync.port_map(a.data)), original_ports)
        self.assertEqual(sync.port_map(b.data)[40002]["quota"]["left"], 60)
        self.assertIn(40005, sync.port_map(b.data))

    def test_empty_good_source_can_delete_after_explicit_count(self):
        a, b, events = pair("hy2")
        a.data["nodes"] = []
        answers = iter(("APPLY", "DELETE 3"))
        result, lines = self.run_case(a, b, apply=True, ask=lambda _: next(answers))
        self.assertEqual(result, 0, lines)
        self.assertEqual(events, [("lock", b.ident["host"]), ("delete", 40002), ("delete", 40005), ("delete", 40013)])

    def test_both_no_reset_are_valid_and_zero_can_be_a_balance(self):
        a, b, _ = pair("hy2")
        a.data["nodes"][0]["quota"]["left"] = 0
        b.data["nodes"][0]["quota"].update(next=0, period=0)
        plan = sync.make_plan(a.data, b.data, {})
        self.assertFalse(plan["issues"])
        self.assertEqual(plan["balances"][0]["source"]["quota"]["left"], 0)

    def test_new_time_anchor_and_reset_values_are_exact(self):
        now = int(time.time())
        row = node("vless", 40002, "x", 88)
        sync.fresh_reference(dict(row, sampled_at=now))
        with self.assertRaisesRegex(sync.SyncError, "采样已经过时"):
            sync.fresh_reference(dict(row, sampled_at=now - 120))
        quota = dict(row["quota"], next=NOW - 30, period=2592000)
        with self.assertRaisesRegex(sync.SyncError, "到计划重置"):
            sync.alive(dict(row, quota=quota))


class ProtocolTests(unittest.TestCase):
    def test_source_session_reads_inventory_and_one_without_target_operations(self):
        row = node("hy2", 40002, "fixture", 60)
        snapshot = inventory("hy2", row)
        host = mock.Mock(spec=["host", "boot", "inventory", "one", "absent"])
        host.host = snapshot["host"]
        host.boot = snapshot["boot"]
        host.inventory.return_value = snapshot
        host.one.return_value = row
        host.absent.return_value = NOW
        factory = mock.Mock(return_value=host)
        requests = [dict(op="hello", protocol="hy2", role="source"), dict(op="inventory"), dict(op="one", row=row),
                    dict(op="absent", port=40005, revision=snapshot["source_revision"])]
        denied_ops = ("lock", "prepare", "journal", "create", "balance", "delete", "recover")
        requests.extend(dict(op=op) for op in denied_ops)
        request_bytes = io.BytesIO()
        for request in requests:
            sync.send_wire(request_bytes, request)
        request_bytes.seek(0)
        response_bytes = io.BytesIO()
        with mock.patch.object(sys, "stdin", mock.Mock(buffer=request_bytes)), \
             mock.patch.object(sys, "stdout", mock.Mock(buffer=response_bytes)):
            sync.serve(factory=factory, check_root=False)
        factory.assert_called_once_with("hy2", role="source")
        response_bytes.seek(0)
        self.assertTrue(sync.read_wire(response_bytes)["ok"])
        self.assertEqual(sync.read_wire(response_bytes), dict(ok=True, result=snapshot))
        self.assertEqual(sync.read_wire(response_bytes), dict(ok=True, result=row))
        self.assertEqual(sync.read_wire(response_bytes), dict(ok=True, result=NOW))
        host.absent.assert_called_once_with(40005, snapshot["source_revision"])
        for op in denied_ops:
            with self.subTest(op=op):
                self.assertFalse(sync.read_wire(response_bytes)["ok"])
        self.assertIsNone(sync.read_wire(response_bytes))

    @unittest.skipUnless(os.name == "posix", "需要 Bash")
    def test_linux_readme_launcher_pins_commit_and_removes_local_download(self):
        source = Path(sync.__file__).resolve()
        readme = source.with_name("README.md").read_text(encoding="utf-8")
        line = re.search(r"```bash\n(bash -c [^\n]+)\n```", readme)[1]
        commit = "a" * 40
        with tempfile.TemporaryDirectory(dir=os.environ.get("HY2_VLESS_TEST_TMP")) as temp:
            root = Path(temp).resolve()
            curl = root / "curl"
            used = root / "download-path"
            mktemp = root / "mktemp"
            mktemp.write_text('#!/bin/bash\nexec /usr/bin/mktemp "$HVS_TMP/hvs.XXXXXXXX"\n')
            mktemp.chmod(0o755)
            curl.write_text('#!/bin/bash\nset -eu\n[[ "$*" == *"/test/repo/$HVS_REF/node_sync.py"* ]]\n'
                            'file=${@: -1}\nprintf %s "$file" >"$HVS_MARKER"\ncp -- "$HVS_ENGINE" "$file"\n')
            curl.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", HVS_REF=commit, HVS_TMP=str(root),
                       HVS_MARKER=str(used), HVS_ENGINE=str(source))
            pinned = re.search(r" _ '[^']+?/[^']+' '[0-9a-f]{40}' --compare$", line)
            self.assertIsNotNone(pinned, "README launcher needs a repository and a full commit SHA")
            command = line[:pinned.start()] + f" _ 'test/repo' '{commit}' --compare --help"
            result = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--apply", result.stdout)
            self.assertFalse(Path(used.read_text()).exists())

    @unittest.skipUnless(Path("/proc/sys/kernel/random/boot_id").is_file(), "需要 Linux 主机标识")
    def test_remote_bootstrap_and_frame_protocol(self):
        path = Path(sync.__file__)
        engine = path.read_bytes()
        # The local test process exercises the exact SSH stdin bootstrap without root.
        engine += b"\nreal_serve = serve\nserve = lambda: real_serve(check_root=False)\n"
        proc = subprocess.Popen([sys.executable, "-IB", "-u", "-c", sync.REMOTE_BOOT],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            proc.stdin.write(str(len(engine)).encode("ascii") + b"\n" + engine)
            reply = dict(op="hello", protocol="hy2", role="source")
            sync.send_wire(proc.stdin, reply)
            hello = sync.read_wire(proc.stdout)
            self.assertTrue(hello["ok"], hello)
            self.assertEqual(hello["result"]["version"], sync.WIRE_VERSION)
            for op in ("lock", "prepare", "journal", "create", "balance", "delete", "recover"):
                with self.subTest(op=op):
                    sync.send_wire(proc.stdin, dict(op=op))
                    denied = sync.read_wire(proc.stdout)
                    self.assertFalse(denied["ok"], denied)
                    self.assertIn("来源", denied["error"])
        finally:
            proc.stdin.close()
            proc.wait(timeout=5)
            proc.stdout.close()

    def test_windows_launcher_has_no_bom_for_powershell_scriptblock(self):
        launcher = Path(sync.__file__).resolve().with_name("start-sync.ps1")
        # Windows PowerShell 5.1 preserves the BOM in Invoke-WebRequest.Content.
        self.assertFalse(launcher.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_malformed_frame_and_duplicate_wg_config(self):
        with self.assertRaisesRegex(sync.SyncError, "数据帧"):
            sync.read_wire(io.BytesIO(b'{"op":"hello"}'))
        with self.assertRaisesRegex(sync.SyncError, "重复"):
            sync.parse_wg_mapping(["wg-a=wg-b", "wg-a=wg-c"])


if __name__ == "__main__":
    unittest.main()
