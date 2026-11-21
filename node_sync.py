#!/usr/bin/env python3
"""One-shot, port-based HY2 and VLESS mirror through OpenSSH."""

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import textwrap
import time
import unicodedata
import uuid
import secrets
import tempfile
from decimal import Decimal, localcontext


PROTOCOLS = {
    "hy2": ("hy2", "hy2", "hy2-temp-", "quota.lock"),
    "vless": ("vless-reality", "vr", "vless-temp-", "portquota.lock"),
}
NODE_ID = re.compile(r"[A-Za-z0-9._-]{1,96}\Z")
BEIJING = dt.timezone(dt.timedelta(hours=8))
MAX_BYTES = (1 << 63) - 1
MAX_INPUT = 16 * 1024 * 1024
MAX_PROGRAM = 512 * 1024
WIRE_VERSION = 2


class SyncError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SyncError(message)


def integer(value, field, minimum=0, maximum=MAX_BYTES):
    if type(value) is str and re.fullmatch(r"[0-9]{1,19}", value):
        value = int(value)
    require(type(value) is int and minimum <= value <= maximum, f"{field} 数值异常")
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path):
    # Native metadata is data. It may contain credentials, so never source or echo it.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), f"{path.name} 不是普通文件")
        data = stream.read(MAX_INPUT + 1)
        require(len(data) <= MAX_INPUT, f"{path.name} 超出读取大小")
    return data, info


def read_meta(path):
    data, info = read_file(path)
    values = {}
    for line in data.decode("utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            require(key not in values, f"{path.name} 包含重复字段 {key}")
            values[key] = value
    revision = digest(f"{info.st_ino}:{info.st_mtime_ns}:".encode() + data)
    return values, revision


def file_revision(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextlib.contextmanager
def readonly_lock(path):
    import fcntl

    # Reuse the same inode as the installed manager without creating/truncating files.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), f"{path.name} 状态异常")
        deadline = time.monotonic() + 60
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, f"{path.name} 忙，请稍后重新预检")
                time.sleep(0.1)
        yield


@contextlib.contextmanager
def finish_current_port():
    interrupted = []

    def remember(number, _frame):
        interrupted.append(number)

    previous = {sig: signal.signal(sig, remember) for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}
    try:
        yield interrupted
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)




# Byte-for-byte contents emitted by the reviewed upstream installers.
NATIVE_SHA256 = {
    "hy2": {
        "common.sh": "98d961c9ecb83b7fb3dfc3762a61407027a34e246d2bde910c9126abd75576f6",
        "quota-lib.sh": "88adf6ee4e8a773ea798d4de332a49ee6774f30f701f7957fb974db0c63ea516",
        "iplimit-lib.sh": "29929bf2144ff242866e3c40de2a6200431c73e39cc7b93177bba3440004c284",
        "hy2_audit.sh": "c0aed4907dd9219b82c906ad0588c2091c17640b360c7b6cdf2c418cc35ff8c5",
        "hy2_mktemp.sh": "43dbfeadde7a30f84d5a30c5837bf5ab912b2296f6a1ef621bef0219804a6bac",
        "hy2_cleanup_one.sh": "e63cfe4d237500b09fb51aa7cdcac22a16f92e1b188982fa5b1e6e52fd3ee36a",
        "hy2_run_temp.sh": "da952977a13f41c956929b0c9fd4a6458ec1241f86401822ec99124f490b207b",
        "hy2_temp_sub.sh": "463774c0dfd9ffa30464dbf6ecd64b7c5d52baf8753d275284c13196cbdce4d2",
        "hy2_mktemp_nat.sh": "12925166261d4ed46884f95da587a9e29ecacdf1580d1d06c6436fa73b825cee",
        "hy2_nat_preflight.sh": "54aa3a961a1b422af74e2cd902e89d4e3dc0c65400718fe63abc66a41a440e7d",
        "pq_reset_due.sh": "f3772a77b7ee9d5470258af8c2d7159c8b90bf1f2dee2309080b1bdee9cce986",
    },
    "vless": {
        "common.sh": "4a1a77e9e2ccfe057412f1d094892b7fde9ece56923f98181ee92611e801eeda",
        "quota-lib.sh": "7cd701d0d2113135cb80e887cba0f807a713a276a8d177b26acc0327c37e0a33",
        "quota-query.py": "abd30ef463bd157bcef9bd464517174375638688dea9de223bfd23b0c17146b2",
        "iplimit-lib.sh": "86b2b49aa59bb0be1c83b9f7b76cdb4e4fe511143840ff3160641e88d9b605e3",
        "vless_audit.sh": "4ee0dcccfa337197b680b6de4a65ae1beed17b2b586094900191c0ec374a53c8",
        "vless_mktemp.sh": "611d55693a6d2337fd9b89eb46852fe994942d1ae13163bd55c1cf533ecc9685",
        "vless_cleanup_one.sh": "fdb670e0c97469a4ac6d572fd947e9696e58160dcbca3d1569b23d7ef3be7e91",
        "vless_run_temp.sh": "4f49addf4c09033d60ae5ad547fd391fad7e3f805013cb5c4558de1901530d27",
        "vless_temp_sub.sh": "8f09bbfc1eba4918082cf575f95cdae73232d5f1b448a55d70e8e2a9ba5f126d",
        "vless_mktemp_nat.sh": "867f3973343b9a861b21fcb8ca3e28ba77b3edce0e345630a3dffd9d335559e6",
        "vless_nat_preflight.sh": "c728158d5ef5cbc4a6595cd0bdb8fa4eb0a7b87e6b449d4397adeb02f4895c31",
        "pq_reset_due.sh": "390f7469aafe8a16845b9f3e662bc10df4326d985b51376abe1788a5e6c765e1",
    }
}
SCHEDULE = {
    "total": "ORIGINAL_LIMIT_BYTES",
    "period": "RESET_INTERVAL_SECONDS",
    "next": "NEXT_RESET_EPOCH",
    "created": "CREATED_EPOCH",
    "last": "LAST_RESET_EPOCH",
    "duration": "DURATION_SECONDS",
    "expires": "EXPIRE_EPOCH",
}

READ_NATIVE = r'''set -euo pipefail
source "$1"
prefix=$2
shift 2
"$prefix"_pq_snapshot_unlocked "$@"
'''

WRITE_NATIVE = r'''set -euo pipefail
trap '' INT TERM HUP
source "$1"
prefix=$2
shift 2
"$prefix"_pq_write_meta "$@" &&
  "$prefix"_pq_rebuild_port "$1" "$4" &&
  "$prefix"_meta_upsert "$("$prefix"_quota_meta_file "$1")" REBUILD_PENDING 0
'''

READ_IP = r'''set -euo pipefail
source "$1"
prefix=$2
shift 2
"$prefix""_il_$1" "$2"
'''

RECOVER_QUOTA = r'''set -euo pipefail
trap '' INT TERM HUP
source "$1"
prefix=$2
meta=$("$prefix"_quota_meta_file "$3")
if [[ "$4" == reset ]]; then
  "$prefix"_pq_reset_due_one "$meta"
else
  "$prefix"_pq_rebuild_port "$3" "$5" &&
    "$prefix"_meta_upsert "$meta" REBUILD_PENDING 0
fi
'''


def exact_replace(text, old, replacement, count=1):
    require(text.count(old) == count, "原生脚本的受支持入口与适配器不一致")
    return text.replace(old, replacement)


def audit_program(text, protocol, prefix, directory, *, source_only=False):
    # Keep the native audit and its exit status, capture its rows before rendering.
    text = exact_replace(text, 'TMP_ROWS="$(mktemp)"\ntrap \'rm -f "$TMP_ROWS"\' EXIT\n', '')
    text = exact_replace(text, ' >>"$TMP_ROWS"', '', 2)
    text = exact_replace(text, f'{prefix}_ensure_runtime_dirs\n', '')
    text = exact_replace(text, f"""sort -t $'\t' -k3,3n "$TMP_ROWS" | /usr/local/lib/{directory}/render_table.py {protocol}\n""".replace("\t", "\\t"), '')
    if protocol == "hy2":
        text = exact_replace(text, 'main_port="$(hy2_main_port)"', 'main_port="$HVS_MAIN_PORT"')
    else:
        text = exact_replace(text, '''  MAIN_PORT="$(vr_meta_get "$VR_MAIN_STATE_FILE" PORT 2>/dev/null || true)"
  if [[ ! "$MAIN_PORT" =~ ^[0-9]+$ ]]; then
    vr_load_defaults >/dev/null 2>&1 || true
    MAIN_PORT="${PORT:-443}"
  fi
''', '  MAIN_PORT="$HVS_MAIN_PORT"\n')
    if not source_only:
        return text

    # Omit lock acquisition and call the audited readers directly on the source.
    for name in ("common.sh", "quota-lib.sh", "iplimit-lib.sh"):
        text = exact_replace(text, f"source /usr/local/lib/{directory}/{name}\n", "")
    if protocol == "vless":
        text = exact_replace(text, '''if [[ "${VR_TEMP_LOCK_HELD:-0}" != "1" ]]; then
  vr_acquire_lock_fd 7 "${VR_LOCK_DIR}/temp.lock" 120 "temp 锁繁忙"
  export VR_TEMP_LOCK_HELD=1
fi
''', "")
        text = exact_replace(text, "\nvr_il_lock\n", "\n")
        for function in ("vr_il_state", "vr_il_family_guard_state"):
            text = exact_replace(text, f"{function} ", f"{function}_unlocked ")
    text = exact_replace(text, f"\n{prefix}_pq_lock\n", "\n")
    return exact_replace(text, f"{prefix}_pq_snapshot ", f"{prefix}_pq_snapshot_unlocked ")


def creator_program(text, prefix):
    # The installed native file remains untouched. Install the exact timestamps and
    # the inherited budget inside the creator, before its normal systemd startup.
    text = exact_replace(text, 'CREATE_EPOCH="$(date +%s)"', 'CREATE_EPOCH="$HVS_CREATED"')
    text = exact_replace(text, f'{prefix}_pq_add_managed_port "$PORT"', 'hvs_initial_quota "$PORT"')
    text = exact_replace(text, f'PQ_LIMIT_BYTES="$({prefix}_parse_gib_to_bytes "$PQ_GIB")"',
                         'PQ_LIMIT_BYTES="$HVS_TOTAL"')
    check = f'[[ "$({prefix}_pq_state "$port")" == "active" ]] || return 1'
    text = exact_replace(text, check,
                         f'case "$({prefix}_pq_state "$port")" in active|exhausted) : ;; *) return 1 ;; esac')
    hook = f'''
hvs_initial_quota() {{
  [[ "$2" == "$HVS_TOTAL" && "$6" == "$HVS_EXPIRES" ]] || return 1
  {prefix}_pq_lock
  {prefix}_pq_write_meta "$1" "$HVS_TOTAL" "$((HVS_TOTAL - HVS_LEFT))" "$HVS_LEFT" "$3" "$4" \\
    "$HVS_QDURATION" "$HVS_QEXPIRES" "$HVS_NEXT" "$HVS_PERIOD" "$HVS_QCREATED" "$HVS_QLAST" "$(date +%s)" 1 \\
    && {prefix}_pq_rebuild_port "$1" "$HVS_LEFT" \\
    && {prefix}_meta_upsert "$({prefix}_quota_meta_file "$1")" REBUILD_PENDING 0
}}
'''
    return hook + text


def beijing(epoch):
    try:
        return dt.datetime.fromtimestamp(epoch, BEIJING).strftime("%Y-%m-%d %H:%M:%S") if epoch else "无"
    except (OverflowError, ValueError, OSError):
        return str(epoch)


def machine_ids():
    with open("/proc/sys/kernel/random/boot_id", "rb", buffering=0) as stream:
        boot = str(uuid.UUID(stream.read(128).strip().decode("ascii")))
    machine = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[0-9a-fA-F]{32}", machine), "VPS 的 machine-id 无效")
    return digest(machine.lower().encode()), boot


def schedule(quota):
    return {key: quota[key] for key in SCHEDULE} if quota else None


def stable(row):
    fields = ("port", "tag", "generation", "expires", "duration", "unit_hash", "landing", "family",
              "ip_limit", "sticky", "wg", "handshake")
    return [row.get(key) for key in fields] + [schedule(row["quota"])]


def port_map(inventory):
    return {row["port"]: row for row in inventory["nodes"]}


def alive(row):
    now = int(time.time())
    require(row["expires"] > now, f"端口 {row['port']} 已到期")
    quota = row["quota"]
    require(not quota or not quota["next"] or quota["next"] > now,
            f"端口 {row['port']} 已到计划重置时间，请等原生重置完成")


def fresh_sample(sampled_at):
    age = int(time.time()) - integer(sampled_at, "来源采样时间", 1)
    require(-30 <= age <= 30, "来源采样已经过时或两端时钟差过大，请重新预检")


def fresh_reference(source):
    alive(source)
    fresh_sample(source.get("sampled_at"))


class Native:
    def __init__(self, protocol, *, role="target"):
        self.protocol = protocol
        self.role = role
        self.directory, self.prefix, self.tag_prefix, self.quota_lock = PROTOCOLS[protocol]
        self.lib = Path("/usr/local/lib") / self.directory
        self.state = Path("/var/lib") / self.directory
        self.runtime = Path("/run") / self.directory
        self.sbin = Path("/usr/local/sbin")
        self.units = Path("/etc/systemd/system")
        self.config = Path("/etc/hysteria/temp" if protocol == "hy2" else "/usr/local/etc/xray")
        self.config_extension = ".yaml" if protocol == "hy2" else ".json"
        self.main_name = "hy2.service" if protocol == "hy2" else "main/xray.service"
        self.main_key = "MAIN_PORT" if protocol == "hy2" else "PORT"
        self.wg_dir = Path("/etc/wireguard")
        self.capabilities = NATIVE_SHA256[protocol]
        self.pending = self.state / ".hy2-vless-sync-recovery.json"
        self.host, self.boot = machine_ids()

    def env(self, **extra):
        env = dict(PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME="/root",
                   LANG="C.UTF-8", PYTHONDONTWRITEBYTECODE="1", **extra)
        if self.role == "target":
            env[f"{self.prefix.upper()}_TEMP_LOCK_HELD"] = "1"
        return env

    def run(self, arguments, *, data=None, env=None, timeout=40, allowed=(0,)):
        options = dict(env=self.env() if env is None else env, capture_output=True, encoding="utf-8",
                       errors="replace", timeout=timeout, check=False)
        if data is None:
            options["stdin"] = subprocess.DEVNULL
        else:
            options["input"] = data
        result = subprocess.run([str(arg) for arg in arguments], **options)
        require(result.returncode in allowed, f"{Path(arguments[0]).name} 执行失败（退出码 {result.returncode}）")
        return result

    def bash(self, text, *, env=None, timeout=40, allowed=(0,)):
        return self.run(("/bin/bash", "--noprofile", "--norc", "-s"), data=text, env=env,
                        timeout=timeout, allowed=allowed)

    def call(self, text, library, *args, quota_lock=False, timeout=40):
        require(self.role == "target", "来源会话仅能执行只读适配器")
        flags = {f"{self.prefix.upper()}_PQ_LOCK_HELD": "1"} if quota_lock else {}
        return self.run(("/bin/bash", "--noprofile", "--norc", "-c", text, "node-sync", self.lib / library,
                         self.prefix, *args), env=self.env(**flags), timeout=timeout).stdout.strip()

    def source_bash(self, text, libraries, *, timeout=40, allowed=(0,), **extra):
        # Execute verified copies. A concurrent native update cannot swap the
        # path between the hash check and Bash loading the library.
        program = [self.checked("common.sh")]
        for name in libraries:
            library = exact_replace(self.checked(name), f"source {self.lib}/common.sh\n", "")
            if name == "quota-lib.sh" and self.protocol == "vless":
                extra["HVS_QUOTA_QUERY"] = self.checked("quota-query.py")
                library = exact_replace(library, 'python3 "${VR_BASE_DIR}/quota-query.py" live "$port"',
                                        'python3 -IB -c "$HVS_QUOTA_QUERY" live "$port"')
            program.append(library)
        program.append(text)
        script = "\n".join(program)
        # Bash can spool these redirections to a temporary file. The pinned
        # readers' quoted Python bodies and here strings need only memory and pipes.
        script = re.sub(r"python3 - ([^\n]+?) <<'(\w+)'\n(.*?)^\2\n",
                        lambda m: f"python3 -IB -c {shlex.quote(m[3])} {m[1]}\n", script, flags=re.M | re.S)
        script = re.sub(r'<<<(".*")(?= \||$)', lambda m: f"< <(printf '%s\\n' {m[1]})", script, flags=re.M)
        return self.bash(script, env=self.env(**extra), timeout=timeout, allowed=allowed)

    def checked(self, name):
        path = (self.lib if name in ("common.sh", "quota-lib.sh", "iplimit-lib.sh", "quota-query.py") else self.sbin) / name
        data, info = read_file(path)
        hash_value = digest(data)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, f"{path} 所有者或权限异常")
        require(hash_value == self.capabilities.get(name), f"未适配原生文件 {path}（SHA-256 {hash_value}）")
        return data.decode("utf-8")

    def locked(self):
        require(self.role == "target", "来源会话不获取原生节点锁")
        return readonly_lock(self.runtime / "temp.lock")

    def quota_locked(self):
        require(self.role == "target", "来源会话不获取原生配额锁")
        return readonly_lock(self.runtime / self.quota_lock)

    def paths(self, tag):
        require(tag.startswith(self.tag_prefix) and NODE_ID.fullmatch(tag[len(self.tag_prefix):]),
                "临时节点标签无效")
        return (self.state / "temp" / f"{tag}.env", self.config / f"{tag}{self.config_extension}",
                self.units / f"{tag}.service", self.state / "temp" / f"{tag}.url")

    def main_port(self):
        meta, _ = read_meta(self.state / "main/main.env")
        return integer(meta.get(self.main_key), "主节点端口", 1, 65535)

    def protected(self, port):
        require(port not in (443, self.main_port()), f"端口 {port} 是受保护端口")

    def read_tag(self, tag):
        meta, _ = read_meta(self.paths(tag)[0])
        require(meta.get("TAG") == tag, "节点 TAG 与原生文件名不一致")
        port = integer(meta.get("PORT"), "端口", 1, 65535)
        self.protected(port)
        created = integer(meta.get("CREATE_EPOCH"), "创建时刻", 1)
        expires = integer(meta.get("EXPIRE_EPOCH"), "到期时刻", 1)
        duration = integer(meta.get("DURATION_SECONDS"), "有效期", 1, 2147483647)
        require(created + duration == expires and created <= int(time.time()), "节点时间字段不一致")
        landing = meta.get("LANDING") or "local"
        family = meta.get("IP_VERSION") or "4"
        require(landing in ("local", "nat") and family in ("4", "6"), "出口类型或入站地址族无法转换")
        ip_limit = integer(meta.get("IP_LIMIT"), "IP 上限", maximum=65535)
        sticky = integer(meta.get("IP_STICKY_SECONDS"), "Sticky 秒数", 1, 2147483647)
        credential = meta.get("PASSWORD" if self.protocol == "hy2" else "UUID")
        require(bool(credential), "节点元数据缺少协议凭据")
        generation = digest(f"{tag}|{port}|{created}|{credential}".encode())
        row = dict(port=port, tag=tag, generation=generation, created=created, expires=expires, duration=duration,
                   landing=landing, family=family, ip_limit=ip_limit, sticky=sticky, quota=None)
        if landing == "nat":
            row["wg"] = wg_interface(meta.get("WG_IF"))
            row["handshake"] = integer(meta.get("HANDSHAKE_MAX", "180"), "WireGuard 握手时限", 1, 86400)
        return row, meta

    def node_files(self, row, meta):
        _, cfg, unit, url = self.paths(row["tag"])
        port, tag = row["port"], row["tag"]
        cfg_data = read_file(cfg)[0].decode("utf-8")
        if self.protocol == "hy2":
            listen, = re.findall(r"^listen:\s*([^\n]+)$", cfg_data, re.M)
            require(listen.strip().strip('"\'').rsplit(":", 1)[-1] == str(port), "HY2 监听与端口不一致")
        else:
            inbounds = json.loads(cfg_data)["inbounds"]
            require(len(inbounds) == 1 and inbounds[0]["port"] == port and inbounds[0]["protocol"] == "vless",
                    "VLESS 入站配置与端口不一致")
        raw_unit, info = read_file(unit)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "原生临时服务权限异常")
        expected = {
            f"ExecStart={self.sbin}/{self.protocol}_run_temp.sh {tag} {cfg}",
            f"ExecStopPost={self.sbin}/{self.protocol}_cleanup_one.sh {tag} --from-stop-post",
        }
        if row["landing"] == "nat":
            expected.add(f"ExecStartPre={self.sbin}/{self.protocol}_nat_preflight.sh {tag}")
        unit_text = raw_unit.decode("utf-8")
        require("\\\n" not in unit_text, "临时服务含有非原生续行")
        actual = [line.strip() for line in unit_text.splitlines() if re.match(r"\s*Exec\w+\s*=", line)]
        require(len(actual) == len(expected) and set(actual) == expected, "临时服务执行入口非原生")
        check = self.run(("systemctl", "show", "--no-pager", "-p", "FragmentPath", "-p", "DropInPaths",
                          "-p", "MainPID", "-p", "ActiveState", "-p", "ControlGroup", f"{tag}.service")).stdout
        props = dict(line.split("=", 1) for line in check.splitlines() if "=" in line)
        require(props.get("FragmentPath") == str(unit) and not props.get("DropInPaths"),
                "检测到自定义服务路径或覆盖设置")
        require(props.get("ActiveState") == "active" and integer(props.get("MainPID"), "主 PID") > 0,
                "原生临时服务未运行")
        self.check_listener(port, props.get("ControlGroup", ""))
        uri = read_file(url)[0].strip()
        scheme = b"hy2://" if self.protocol == "hy2" else b"vless://"
        require(uri.startswith(scheme) and b"\n" not in uri and b"\r" not in uri, "原生节点链接无效")
        row["unit_hash"] = digest(raw_unit + b"\0" + cfg_data.encode())

    def check_listener(self, port, cgroup):
        require(cgroup.startswith("/"), "临时节点缺少原生服务控制组")
        option = "-lunp" if self.protocol == "hy2" else "-ltnp"
        sockets = self.run(("ss", "-H", option, "sport", "=", f":{port}")).stdout.splitlines()
        require(sockets, "原生临时端口未监听")
        for line in sockets:
            pids = set(re.findall(r"\bpid=(\d+)\b", line))
            require(pids, "无法确认端口监听进程")
            for pid in pids:
                proc = (Path("/proc") / pid / "cgroup").read_text(encoding="utf-8")
                groups = [entry.split(":", 2)[-1] for entry in proc.splitlines()]
                require(any(group == cgroup or group.startswith(cgroup + "/") for group in groups),
                        f"端口 {port} 由另一服务监听")

    def raw_quota(self, port, tag, declared):
        path = self.state / "quota" / f"{port}.env"
        if not (path.exists() or path.is_symlink()) and not declared:
            return None, None
        raw, _ = read_meta(path)
        require(raw.get("OWNER_KIND") == "temp" and raw.get("OWNER_TAG") == tag
                and raw.get("PORT") == str(port), "配额归属与节点不一致")
        data = {key: integer(raw.get(field), field, 1 if key == "total" else 0)
                for key, field in SCHEDULE.items()}
        require(integer(declared, "节点原始总配额", 1) == data["total"], "原始总配额与节点元数据不一致")
        require(bool(data["period"]) == bool(data["next"]), "重置周期与下次重置时刻不一致")
        stored_left = integer(raw.get("LIMIT_BYTES"), "保存余额", maximum=data["total"])
        saved = integer(raw.get("SAVED_USED_BYTES"), "保存已用量", maximum=data["total"])
        require(saved + stored_left == data["total"], "持久配额的已用与余额不一致")
        data["stored"] = stored_left
        return data, raw.get("REBUILD_PENDING", "0")

    def quota(self, row, meta):
        path = self.state / "quota" / f"{row['port']}.env"
        revision = file_revision(path) if self.role == "source" else None
        q, pending = self.raw_quota(row["port"], row["tag"], meta.get("PQ_LIMIT_BYTES"))
        require(pending in (None, "0"), "原生配额待恢复")
        if q is not None:
            require(q["expires"] in (0, row["expires"]) and q["duration"] in (0, row["duration"]),
                    "节点到期或有效期与配额元数据不一致")
        if self.role == "source":
            probe = f'{self.prefix}_pq_snapshot_unlocked "$HVS_PORT"\n'
            value = self.source_bash(probe, ("quota-lib.sh",), HVS_PORT=str(row["port"])).stdout.strip()
            require(file_revision(path) == revision, f"端口 {row['port']} 的来源配额在采样中变化")
        else:
            value = self.call(READ_NATIVE, "quota-lib.sh", row["port"], quota_lock=True)
        fields = value.split("|")
        require(len(fields) == 4, "原生实时配额输出不完整")
        total, used, left = (integer(value, "实时配额字节") for value in fields[1:])
        if q is None:
            require(fields == ["none", "0", "0", "0"], "无配额节点存在异常计费状态")
            return None
        require(fields[0] in ("active", "exhausted") and total == q["total"] and used + left == total
                and (fields[0] == "exhausted") == (left == 0), "内核实时配额状态异常")
        return dict(q, left=left)

    def ip_policy(self, row):
        path = self.state / "iplimit" / f"{row['port']}.env"
        kind = "family_guard_state"
        if row["ip_limit"]:
            meta, _ = read_meta(path)
            require(meta.get("OWNER_KIND") == "temp" and meta.get("OWNER_TAG") == row["tag"]
                    and meta.get("PORT") == str(row["port"]) and meta.get("IP_VERSION", "4") == row["family"]
                    and integer(meta.get("IP_LIMIT"), "来源 IP 上限") == row["ip_limit"]
                    and integer(meta.get("IP_STICKY_SECONDS"), "Sticky 秒数") == row["sticky"],
                    "来源 IP 策略归属或配置不一致")
            kind = "state"
        else:
            require(not path.exists() and not path.is_symlink(), "无 IP 上限节点存在额外手工 IP 策略")
        if self.role == "source":
            probe = f'{self.prefix}_il_{kind}_unlocked "$HVS_PORT"\n'
            state = self.source_bash(probe, ("iplimit-lib.sh",), HVS_PORT=str(row["port"])).stdout.strip()
        else:
            state = self.call(READ_IP, "iplimit-lib.sh", kind, row["port"])
        require(state == "active", "内核 IP 防护状态异常")

    def native_audit(self, main):
        script = self.checked(f"{self.protocol}_audit.sh")
        source = self.role == "source"
        program = audit_program(script, self.protocol, self.prefix, self.directory, source_only=source)
        allowed = (0, 1) if self.protocol == "vless" else (0,)
        if source:
            raw = self.source_bash(program, ("quota-lib.sh", "iplimit-lib.sh"), timeout=180,
                                   allowed=allowed, HVS_MAIN_PORT=str(main))
        else:
            upper = self.prefix.upper()
            with self.quota_locked(), readonly_lock(self.runtime / "iplimit.lock"):
                raw = self.bash(program, timeout=180, allowed=allowed, env=self.env(
                    HVS_MAIN_PORT=str(main), **{f"{upper}_PQ_LOCK_HELD": "1", f"{upper}_IL_LOCK_HELD": "1"}))
        rows = {}
        for line in raw.stdout.splitlines():
            fields = line.split("\t")
            require(len(fields) == (16 if self.protocol == "hy2" else 15), "原生审计行格式异常")
            name, state, port = fields[:3]
            if self.protocol == "hy2" and name != self.main_name:
                require(name.endswith(".service"), "原生 HY2 审计服务名异常")
                name = name[:-8]
            require(name not in rows, "原生审计包含重复服务")
            rows[name] = dict(port=integer(port, "审计端口", 1, 65535), active=state == "active",
                              listen=fields[3 if self.protocol == "hy2" else 4] == "yes")
        return rows, raw.returncode

    def occupied_ports(self):
        lines = self.run(("ss", "-H", "-lntu")).stdout.splitlines()
        ports = set()
        for line in lines:
            fields = line.split()
            require(len(fields) >= 6 and fields[0] in ("tcp", "udp"), "无法判断目标监听端口")
            # ss with both -t and -u prints Netid, State, Recv-Q, Send-Q, Local, Peer.
            port = fields[4].rsplit(":", 1)[-1]
            ports.add(integer(port, "监听端口", 1, 65535))
        return ports

    def managed_rules(self, kinds=("pq", "iplimit")):
        output = json.loads(self.run(("nft", "-j", "list", "tables")).stdout)["nftables"]
        tables = {item["table"]["name"] for item in output
                  if "table" in item and item["table"]["family"] == "inet"}
        ports = set()
        for table in (f"{self.prefix}_{kind}" for kind in kinds):
            if table in tables:
                listing = self.run(("nft", "-a", "list", "table", "inet", table)).stdout
                ports.update(map(int, re.findall(rf'comment "{self.prefix}-(?:pq|il)-[^"]+?-(\d+)"', listing)))
                ports.update(map(int, re.findall(rf"\b{self.prefix}_(?:pq_(?:in|out|q)_|il[46]_)(\d+)\b", listing)))
        return ports

    def policy_ports(self, indexed, issues):
        ports = set()
        for directory in ("quota", "iplimit"):
            for path in sorted((self.state / directory).iterdir()):
                if not path.name.endswith(".env"):
                    if ".tmp." in path.name:
                        issues.append(f"{path.name} 有未完成的原生写入")
                    continue
                meta, _ = read_meta(path)
                port = integer(meta.get("PORT"), "管理资源端口", 1, 65535)
                require(path.name == f"{port}.env", f"{path.name} 的端口与文件名不符")
                owner = meta.get("OWNER_KIND")
                ports.add(port)
                if owner == "temp":
                    if indexed.get(port) != meta.get("OWNER_TAG"):
                        issues.append(f"端口 {port} 有无法归属的 {directory} 资源")
                elif owner not in ("manual", "main"):
                    issues.append(f"端口 {port} 的 {directory} 所有者无法识别")
        return ports

    def history(self, row, meta, text):
        record = text.get("users", {}).get(row["tag"])
        if not record:
            return {}
        password = (meta["PASSWORD"] if self.protocol == "hy2" else str(uuid.UUID(meta["UUID"])))
        identity = f"{row['tag']}|{row['port']}|{password}|{row['created']}"
        require(record.get("port") == row["port"] and record.get("key") == digest(identity.encode())[:32],
                "每日流量的节点身份不匹配")
        today = dt.datetime.now(BEIJING).date()
        return {day: [integer(values[key], "每日流量") for key in ("upload", "download")]
                for day, values in record["days"].items() if 0 <= (today - dt.date.fromisoformat(day)).days < 30}

    def source_revision(self):
        # Track topology and identities without using locks or comparing live counters.
        watched = [self.state / "main/main.env", self.pending]
        for directory, suffixes, prefix in (
            (self.state / "temp", (".env", ".url"), ""),
            (self.config, (self.config_extension,), self.tag_prefix),
            (self.units, (".service",), self.tag_prefix),
        ):
            watched.append(directory)
            watched.extend(path for path in directory.iterdir()
                           if path.name.startswith(prefix) and path.name.endswith(suffixes))
        return digest(wire_bytes([(str(path), file_revision(path)) for path in sorted(watched)]))

    def absent(self, port, revision):
        require(self.source_revision() == revision, "来源节点清单在删除前变化，请重新对账")
        for path in (self.state / "temp").glob("*.env"):
            meta, _ = read_meta(path)
            require(integer(meta.get("PORT"), "来源临时端口", 1, 65535) != port, f"来源已出现端口 {port}")
            require(integer(meta.get("EXPIRE_EPOCH"), "来源到期时刻", 1) > int(time.time()),
                    "来源有节点已到期，请等原生清理完成后重新对账")
        require(self.source_revision() == revision, "来源节点清单在删除前变化，请重新对账")
        return int(time.time())

    def inventory(self, history=False):
        source = self.role == "source"
        revision = self.source_revision() if source else None
        result = dict(protocol=self.protocol, host=self.host, boot=self.boot, nodes=[], issues=[], main=None,
                      reserved=[], pending=None, reset_timer=False, sampled=int(time.time()))
        issues, rows = result["issues"], result["nodes"]
        temp = self.state / "temp"
        for name in ("common.sh", "quota-lib.sh", "iplimit-lib.sh", f"{self.protocol}_run_temp.sh",
                     f"{self.protocol}_temp_sub.sh", f"{self.protocol}_cleanup_one.sh", "pq_reset_due.sh"):
            self.checked(name)
        main = self.main_port()
        result["main"] = main
        audit, audit_rc = self.native_audit(main)
        main_row = audit.pop(self.main_name, None)
        if main_row != dict(port=main, active=True, listen=True):
            issues.append("原生审计主服务或主端口异常")
        if audit_rc:
            issues.append(f"原生审计返回失败（退出码 {audit_rc}）")
        pending_exists = self.pending.exists() or self.pending.is_symlink()
        if pending_exists:
            recovery = self.load_recovery()
            result["pending"] = {k: recovery[k] for k in ("action", "port", "tag")}
            issues.append(f"端口 {recovery['port']} 有一次未收尾的 {recovery['action']} 操作")

        metas = {path.stem for path in temp.iterdir() if path.name.endswith(".env")}
        result["total"] = len(metas)
        discovered = set(audit)
        for path, suffix in ((temp, ".url"), (self.config, self.config_extension), (self.units, ".service")):
            discovered |= {entry.stem for entry in path.iterdir()
                           if entry.name.startswith(self.tag_prefix) and entry.name.endswith(suffix)}
            if any(entry.name.startswith(self.tag_prefix) and ".tmp." in entry.name for entry in path.iterdir()):
                issues.append(f"{path} 发现未完成的原生文件写入")
        if discovered != metas:
            issues.append(f"审计、配置、链接和元数据清单不完整，未配对标签 {', '.join(sorted(discovered ^ metas))}")
        unique = {}
        history_data = {}
        if history and (self.state / "traffic/daily.json").exists():
            history_data = json.loads(read_file(self.state / "traffic/daily.json")[0])
        for tag in sorted(metas):
            try:
                row, meta = self.read_tag(tag)
                port = row["port"]
                require(port not in unique, f"端口 {port} 存在重复身份")
                unique[port] = tag
                require(audit.get(tag) == dict(port=port, active=True, listen=True),
                        f"端口 {port} 的审计或服务状态异常")
                self.node_files(row, meta)
                self.ip_policy(row)
                with contextlib.nullcontext() if source else self.quota_locked():
                    row["quota"] = self.quota(row, meta)
                alive(row)
                if history:
                    row["history"] = self.history(row, meta, history_data)
                rows.append(row)
            except (SyncError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
                issues.append(f"{tag!r} {safe_error(exc)}")

        with contextlib.ExitStack() as locks:
            if not source:
                locks.enter_context(self.quota_locked())
                locks.enter_context(readonly_lock(self.runtime / "iplimit.lock"))
            quota_ports = self.managed_rules(("pq",))
            native_ports = quota_ports | self.managed_rules(("iplimit",))
            policies = self.policy_ports(unique, issues)
        for row in rows:
            if row["quota"] is None and row["port"] in quota_ports:
                issues.append(f"无配额节点 {row['port']} 存在原生计费规则")
        if native_ports - set(unique) - policies - {main}:
            issues.append("无法归属的原生内核端口 " + ports_text(native_ports - set(unique) - policies - {main}))
        result["reserved"] = sorted(self.occupied_ports() | policies | native_ports | {443, main})
        result["reset_timer"] = self.run(("systemctl", "is-active", "pq-reset.timer"),
                                         allowed=(0, 1, 3, 4)).returncode == 0
        if any(row["quota"] and row["quota"]["period"] for row in rows) and not result["reset_timer"]:
            issues.append("原生配额重置定时器未运行")
        result["nodes"].sort(key=lambda row: row["port"])
        if source:
            if self.source_revision() != revision:
                issues.append("来源节点清单在对账中变化，请重新对账")
            result["source_revision"] = revision
        return result



    def wg_settings(self, interface, handshake):
        path = self.wg_dir / f"{interface}.env"
        _, info = read_file(path)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, f"{path} 所有者或权限异常")
        meta, _ = read_meta(path)
        mark = integer(meta.get("MARK"), "WireGuard mark", 1, (1 << 32) - 1)
        table = integer(meta.get("TABLE_ID"), "WireGuard 路由表", 1, 2147483647)
        priority = integer(meta.get("RULE_PRIORITY"), "WireGuard 路由优先级", 1, 32765)
        require(table not in (253, 254, 255), "WireGuard 使用保留路由表")
        self.run(("systemctl", "is-active", "--quiet", f"wg-quick@{interface}.service"))
        route = self.run(("ip", "-4", "route", "get", "1.1.1.1", "mark", str(mark))).stdout.split()
        require("dev" in route and route[route.index("dev") + 1] == interface, "WireGuard 标记路由不可用")
        result = self.run(("wg", "show", interface, "latest-handshakes")).stdout
        timestamps = [integer(line.split()[-1], "WireGuard 握手时刻") for line in result.splitlines()]
        now = int(time.time())
        require(any(0 <= now - timestamp <= handshake for timestamp in timestamps), "目标 WireGuard 握手已过期")
        for name in ("wg_nat_healthcheck.sh", "wg_nat_guard.sh"):
            require(os.access(self.sbin / name, os.X_OK), f"缺少目标原生 {name}")
        return dict(WG_IF=interface, MARK=str(mark), TABLE_ID=str(table), RULE_PRIORITY=str(priority),
                    HANDSHAKE_MAX=str(handshake))

    def prepare_create(self, row):
        port, mode = row["port"], row["landing"]
        self.protected(port)
        alive(row)
        name = f"{self.protocol}_mktemp.sh"
        options = dict(LANDING=mode) if self.protocol == "hy2" else {}
        if mode == "nat":
            self.checked(f"{self.protocol}_nat_preflight.sh")
            self.checked(f"{self.protocol}_mktemp_nat.sh")
            interface = wg_interface(row.get("target_wg", row.get("wg")))
            options.update(self.wg_settings(interface, row["handshake"]))
            if self.protocol == "vless":
                name = "vless_mktemp_nat.sh"
        script = creator_program(self.checked(name), self.prefix)
        self.run(("/bin/bash", "--noprofile", "--norc", "-n"), data=script)
        if row["quota"] and row["quota"]["period"]:
            self.run(("systemctl", "is-active", "--quiet", "pq-reset.timer"))
        if row["family"] == "6":
            defaults = Path("/etc/default") / ("hy2-main" if self.protocol == "hy2" else "vless-reality")
            key = "HY_IPV6_DOMAIN" if self.protocol == "hy2" else "PUBLIC_IPV6_DOMAIN"
            matches = re.findall(rf"^\s*{key}\s*=(.*)$", read_file(defaults)[0].decode("utf-8"), re.M)
            require(len(matches) == 1 and matches[0].strip().strip('"\''),
                    f"目标缺少 {key}，无法转换 IPv6 发布地址")
        return name, script, options

    def port_unowned(self, port, tag):
        """Check actual native metadata before calling a cleanup, even during recovery."""
        self.protected(port)
        for path in (self.state / "temp").glob("*.env"):
            values, _ = read_meta(path)
            entry_port = integer(values.get("PORT"), "临时节点端口", 1, 65535)
            require(entry_port != port or path.stem == tag, f"端口 {port} 已由其他临时节点使用")
            require(path.stem != tag or entry_port == port, f"{tag} 已指向另一端口")
        for name in ("quota", "iplimit"):
            path = self.state / name / f"{port}.env"
            if path.exists() or path.is_symlink():
                values, _ = read_meta(path)
                require(values.get("OWNER_TAG") == tag and values.get("OWNER_KIND") == "temp"
                        and values.get("PORT") == str(port), f"端口 {port} 的 {name} 属于其他资源")

    def tag_absent(self, port, tag):
        if any(path.exists() or path.is_symlink() for path in self.paths(tag)):
            return False
        if any(self.units.glob(f"*.wants/{tag}.service")) or any(self.units.glob(f"*.requires/{tag}.service")):
            return False
        if any((self.state / name / f"{port}.env").exists() for name in ("quota", "iplimit")):
            return False
        if port in self.managed_rules():
            return False
        status = self.run(("systemctl", "is-active", "--quiet", f"{tag}.service"), allowed=(0, 1, 3, 4))
        listener = self.run(("ss", "-H", "-lnu" if self.protocol == "hy2" else "-lnt",
                             "sport", "=", f":{port}")).stdout
        return status.returncode != 0 and not listener.strip()

    def clean(self, port, tag):
        self.port_unowned(port, tag)
        self.checked(f"{self.protocol}_cleanup_one.sh")
        path = self.sbin / f"{self.protocol}_cleanup_one.sh"
        self.run(("/bin/bash", "--noprofile", "--norc", path, tag), env=self.env(FORCE="1"), timeout=None)
        require(self.tag_absent(port, tag), f"端口 {port} 的原生服务或管理资源尚未清完")

    def one(self, expected):
        port = integer(expected["port"], "端口", 1, 65535)
        source = self.role == "source"
        if source:
            watched = (*self.paths(expected["tag"]), self.state / "main/main.env",
                       *(self.state / kind / f"{port}.env" for kind in ("quota", "iplimit")))
            revision = [file_revision(path) for path in watched]
        row, meta = self.read_tag(expected["tag"])
        require(row["port"] == port, "端口归属已变化")
        self.node_files(row, meta)
        if source:
            self.ip_policy(row)
        with contextlib.nullcontext() if source else self.quota_locked():
            row["quota"] = self.quota(row, meta)
            row["sampled_at"] = int(time.time())
        if source:
            require([file_revision(path) for path in watched] == revision,
                    f"端口 {row['port']} 的来源状态在采样中变化")
        require(stable(row) == stable(expected), f"端口 {row['port']} 的节点或重置计划已变化")
        alive(row)
        return row

    def store_recovery(self, data):
        require(not self.pending.exists() and not self.pending.is_symlink(), "目标存在未收尾操作")
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".hy2-vless-sync-", dir=self.state,
                                         delete=False) as file:
            path = Path(file.name)
            try:
                file.write(wire_bytes(data))
                file.flush()
                os.fsync(file.fileno())
                os.replace(path, self.pending)
                self.sync_state_dir()
            finally:
                if path.exists():
                    path.unlink()

    def load_recovery(self):
        raw, info = read_file(self.pending)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "恢复记录权限异常")
        data = json.loads(raw)
        require(data["version"] == WIRE_VERSION and data["host"] == self.host and data["protocol"] == self.protocol,
                "恢复记录属于另一主机或版本")
        require(data["action"] in ("create", "delete", "balance"), "未知恢复操作")
        self.paths(data["tag"])
        self.protected(integer(data["port"], "恢复端口", 1, 65535))
        return data

    def sync_state_dir(self):
        directory = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def complete(self):
        self.pending.unlink()
        self.sync_state_dir()

    def quota_write(self, row, quota, left):
        self.call(WRITE_NATIVE, "quota-lib.sh", row["port"], quota["total"], quota["total"] - left, left,
                  "temp", row["tag"], quota["duration"], quota["expires"], quota["next"], quota["period"],
                  quota["created"], quota["last"], int(time.time()), 1, quota_lock=True, timeout=None)

    def create(self, source, origin):
        port = source["port"]
        name, script, options = self.prepare_create(source)
        require(port not in self.occupied_ports() and port not in self.managed_rules(), f"端口 {port} 已被占用")
        identifier = f"sync-{source['landing']}-{port}-{secrets.token_hex(5)}"
        tag = self.tag_prefix + identifier
        self.port_unowned(port, tag)
        require(all(not (p.exists() or p.is_symlink()) for p in self.paths(tag)), f"目标标签 {tag} 已存在")
        quota = source["quota"]
        settings = {
            "id": identifier, "D": str(source["duration"]), "PORT_START": str(port), "PORT_END": str(port),
            "MAX_START_RETRIES": "1", "IP_VERSION": source["family"], "IP_LIMIT": str(source["ip_limit"]),
            "IP_STICKY_SECONDS": str(source["sticky"]), "SKIP_HEALTHCHECK": "0",
            "HVS_CREATED": str(source["created"]), "HVS_EXPIRES": str(source["expires"]),
            "PQ_GIB": "",
        }
        if quota is not None:
            with localcontext() as context:
                context.prec = 70
                settings["PQ_GIB"] = format(Decimal(quota["total"]) / (1 << 30), "f")
            for key, env_name in (("total", "TOTAL"), ("left", "LEFT"), ("duration", "QDURATION"),
                                  ("expires", "QEXPIRES"), ("next", "NEXT"), ("period", "PERIOD"),
                                  ("created", "QCREATED"), ("last", "QLAST")):
                settings[f"HVS_{env_name}"] = str(quota[key])
        fresh_reference(source)
        self.store_recovery(dict(version=WIRE_VERSION, host=self.host, protocol=self.protocol, action="create",
                                 source=origin, port=port, tag=tag))
        try:
            try:
                self.bash(script, env=self.env(**settings, **options), timeout=None)
            except SyncError as exc:
                raise SyncError(f"{name} 创建失败（{exc}）") from exc
            row, meta = self.read_tag(tag)
            self.node_files(row, meta)
            self.ip_policy(row)
            with self.quota_locked():
                row["quota"] = self.quota(row, meta)
            keys = ("port", "created", "expires", "duration", "landing", "family", "ip_limit", "sticky")
            require(all(row[k] == source[k] for k in keys) and schedule(row["quota"]) == schedule(quota),
                    "新节点的有效期、出口、IP 或重置计划与来源不一致")
            if row["landing"] == "nat":
                require(row["wg"] == options["WG_IF"] and row["handshake"] == source["handshake"],
                        "新节点的 WireGuard 配置不一致")
            if quota is not None:
                require(row["quota"]["stored"] == quota["left"] and row["quota"]["left"] <= quota["left"],
                        "新节点的本期余额未通过核对")
            alive(row)
        except (SyncError, OSError, TypeError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            try:
                if not self.tag_absent(port, tag):
                    self.clean(port, tag)
                self.complete()
            except (SyncError, OSError, ValueError, subprocess.TimeoutExpired) as rollback:
                raise SyncError(f"创建失败且原生清理未完成（{rollback}），请使用 --recover") from exc
            raise SyncError(f"创建失败，已清除本次节点（{safe_error(exc)}）") from exc
        self.complete()
        return dict(port=port, action="create", tag=tag, expires=row["expires"], quota=row["quota"],
                    landing=row["landing"], family=row["family"],
                    link_command=f"cat -- {shlex.quote(str(self.paths(tag)[3]))}")

    def balance(self, expected, source, origin):
        port, tag = expected["port"], expected["tag"]
        self.protected(port)
        fresh_reference(source)
        row, meta = self.read_tag(tag)
        self.node_files(row, meta)
        with self.quota_locked():
            row["quota"] = before = self.quota(row, meta)
            require(before is not None and source["quota"] and stable(row) == stable(expected),
                    "目标节点身份、配额类型或重置计划已变化")
            alive(row)
            fresh_reference(source)
            left = source["quota"]["left"]
            require(left <= before["total"], "实时来源余额超过目标原始总配额")
            if before["left"] == left:
                return dict(port=port, action="skip", message="实时余额已对齐")
            self.store_recovery(dict(version=WIRE_VERSION, host=self.host, protocol=self.protocol, action="balance",
                                     source=origin, port=port, tag=tag, generation=row["generation"],
                                     before=schedule(before), old_left=before["left"], wanted=left))
            try:
                self.quota_write(row, before, left)
                applied = self.quota(row, meta)
                require(schedule(applied) == schedule(before) and applied["stored"] == left and applied["left"] <= left,
                        "余额或原有重置计划未通过写后核验")
            except (SyncError, OSError, TypeError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
                try:
                    self.quota_write(row, before, before["left"])
                    restored = self.quota(row, meta)
                    require(schedule(restored) == schedule(before) and restored["stored"] == before["left"],
                            "恢复后的余额或重置计划不一致")
                    self.complete()
                except (SyncError, OSError, ValueError, TypeError, subprocess.TimeoutExpired) as rollback:
                    raise SyncError(f"配额写入及复原失败（{safe_error(rollback)}），请使用 --recover") from exc
                raise SyncError(f"配额写入失败，已恢复原余额（{safe_error(exc)}）") from exc
            self.complete()
        return dict(port=port, action="balance", before=before["left"], wanted=left, actual=applied["left"])

    def delete(self, expected, origin, sampled_at):
        row = self.one(expected)
        port, tag = row["port"], row["tag"]
        fresh_sample(sampled_at)
        self.store_recovery(dict(version=WIRE_VERSION, host=self.host, protocol=self.protocol, action="delete",
                                 source=origin, port=port, tag=tag, generation=row["generation"]))
        try:
            self.clean(port, tag)
        except (SyncError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise SyncError(f"原生清理中断（{safe_error(exc)}），请使用 --recover") from exc
        self.complete()
        return dict(port=port, action="delete")

    def recover(self, expected, source):
        record = self.load_recovery()
        require(record == expected and record["source"] == source["host"], "恢复记录或来源主机已变化")
        port, tag, action = record["port"], record["tag"], record["action"]
        self.port_unowned(port, tag)
        if action == "delete":
            require(port not in port_map(source), f"来源重新出现端口 {port}，需人工核对")
        meta_path = self.paths(tag)[0]
        if meta_path.exists() and action in ("delete", "balance"):
            row, meta = self.read_tag(tag)
            require(record["generation"] == row["generation"], "待恢复的端口已换成另一节点")
        if action in ("delete", "create"):
            if action == "delete":
                fresh_sample(source.get("sampled_at"))
            if not self.tag_absent(port, tag):
                self.clean(port, tag)
        else:
            require(meta_path.is_file(), "待恢复配额节点已被移除，请核对")
            with self.quota_locked():
                current, pending = self.raw_quota(port, tag, meta.get("PQ_LIMIT_BYTES"))
                require(current is not None and pending in ("0", "1"), "待恢复的配额数据异常")
                if pending == "1":
                    require(schedule(current) == record["before"] and current["stored"] in
                            (record["wanted"], record["old_left"]), "待重建的配额不属于本轮")
                    require(row["expires"] > int(time.time()), "待恢复节点已到期，请交给原生清理")
                    due = current["next"] and current["next"] <= int(time.time())
                    self.call(RECOVER_QUOTA, "quota-lib.sh", port, "reset" if due else "rebuild", current["stored"],
                              quota_lock=True, timeout=None)
                restored = self.quota(row, meta)
                require(restored and restored["total"] == record["before"]["total"], "恢复后的原始总额不一致")
        self.complete()
        return dict(port=port, action="recover", message=f"已处理本轮 {action}")


def wg_interface(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value) and value not in (".", ".."),
            "WireGuard 接口无法转换")
    return value


def safe_error(exc):
    if isinstance(exc, SyncError):
        return str(exc)
    if isinstance(exc, subprocess.TimeoutExpired):
        return "原生检查超时"
    if isinstance(exc, OSError):
        where = f" {exc.filename!r}" if exc.filename else ""
        return f"I/O 错误{where}（{exc.strerror or type(exc).__name__}）"
    # Do not include untrusted config content or credentials in diagnostics.
    return f"原生数据格式异常（{type(exc).__name__}）"


def ports_text(ports):
    return ", ".join(map(str, sorted(ports))) or "无"


def make_plan(source, target, wg_map):
    a, b = port_map(source), port_map(target)
    missing, extra, matched = set(a) - set(b), set(b) - set(a), set(a) & set(b)
    issues = [f"{side} {error}" for side, data in (("来源", source), ("目标", target)) for error in data["issues"]]
    creates, balances, notes, uncapped = [], [], [], []
    require(source["protocol"] != target["protocol"], "请选择两个不同协议")
    require(source["host"] != target["host"] and source["boot"] != target["boot"],
            "同步需要两台独立 VPS，主机标识不能相同")
    if issues:
        return dict(creates=[], deletes=[], balances=[], uncapped=[], matched=sorted(matched), issues=issues, notes=[])
    protected = {443, source["main"], target["main"]}
    for port in sorted(missing | extra | matched):
        if port in protected:
            issues.append(f"端口 {port} 与任一 VPS 的受保护主服务端口冲突")
    for port in sorted(missing):
        row = dict(a[port])
        if port in target["reserved"]:
            issues.append(f"待创建端口 {port} 已被目标监听或管理资源占用")
        if row["landing"] == "nat":
            row["target_wg"] = wg_map.get(row["wg"], row["wg"])
        if row["quota"] and row["quota"]["period"] and not target["reset_timer"]:
            issues.append(f"端口 {port} 的目标原生重置定时器未运行")
        creates.append(row)
    for port in sorted(matched):
        src, dst = a[port], b[port]
        aq, bq = src["quota"], dst["quota"]
        if src["expires"] != dst["expires"]:
            notes.append(f"端口 {port} 到期差异 {beijing(src['expires'])} → 目标保留 {beijing(dst['expires'])}")
        if (bool(aq) != bool(bq)):
            issues.append(f"端口 {port} 一端无配额，无法在保留目标总配额的同时对齐余额")
        elif aq is None:
            uncapped.append(port)
        else:
            if (aq["total"], aq["period"], aq["next"]) != (bq["total"], bq["period"], bq["next"]):
                notes.append(f"端口 {port} 配额周期差异，目标保留总额 {bq['total']} B、周期 {bq['period']} 秒、"
                             f"下次重置 {beijing(bq['next'])}")
            if aq["left"] > bq["total"]:
                issues.append(f"端口 {port} 来源余额 {aq['left']} B 超过目标原始总额 {bq['total']} B")
            balances.append(dict(port=port, source=src, target=dst, change=aq["left"] != bq["left"]))
    return dict(creates=creates, deletes=[b[p] for p in sorted(extra)], balances=balances, uncapped=uncapped,
                matched=sorted(matched), issues=issues, notes=notes)


def plan_signature(plan):
    return (
        [stable(row) + [row.get("target_wg")] for row in plan["creates"]],
        [stable(row) for row in plan["deletes"]],
        [(stable(item["source"]), stable(item["target"])) for item in plan["balances"]],
        plan["uncapped"], plan["matched"],
    )


def gibibytes(amount):
    size = Decimal(amount) / (1 << 30)
    return "<0.01" if 0 < size < Decimal("0.01") else f"{size:.2f}"


def balance_change(before, after):
    change = after - before
    size = gibibytes(abs(change))
    if size == "<0.01":
        return f"{change:+d} B"
    sign = "+" if change > 0 else "-"
    return f"{sign}{size} GiB"


def display_width(value):
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in value)


def print_table(headers, rows):
    cells = [headers] + [tuple(map(str, row)) for row in rows]
    widths = [max(map(display_width, column)) for column in zip(*cells)]
    for index, row in enumerate(cells):
        print("  ".join(cell + " " * (width - display_width(cell))
                        for cell, width in zip(row, widths)).rstrip())
        if index == 0:
            print("  ".join("-" * width for width in widths))


def outlet(row):
    kind = "WG-NAT" if row["landing"] == "nat" else "本机"
    return f"{kind}/{row['family']}"


def show_plan_details(plan, target):
    if target["nodes"]:
        print("\n当前目标节点")
        print_table(("端口", "出口", "节点标识"), (
            (row["port"], outlet(row), row["tag"])
            for row in sorted(target["nodes"], key=lambda row: row["port"])))
    if not (plan["creates"] or plan["balances"] or plan["notes"]):
        return
    print("\n详细参数")
    for row in plan["creates"]:
        print(f"  {row['port']}  IPv{row['family']}  IP 上限 {row['ip_limit']}  Sticky {row['sticky']} 秒")
        if row["landing"] == "nat":
            print(f"         WireGuard  {row['wg']} → {row['target_wg']}")
        quota = row["quota"]
        if quota:
            print(f"         剩余 {quota['left']} B  总额 {quota['total']} B  重置周期 {quota['period']} 秒")
    for item in plan["balances"]:
        src, dst = item["source"]["quota"], item["target"]["quota"]
        print(f"  {item['port']}  余额 {dst['left']} B → {src['left']} B  目标总额 {dst['total']} B")
    for note in plan["notes"]:
        print(f"  {note}")


def show_history(source, target):
    for side, data in (("来源", source), ("目标", target)):
        for row in data["nodes"]:
            for day, (up, down) in sorted(row.get("history", {}).items()):
                print(f"{side} {row['port']} {day} 上传 {up} B，下载 {down} B")


def show_plan(source, target, plan, *, details=False):
    print(f"\n{source['protocol'].upper()} → {target['protocol'].upper()}  |  同步计划  |  北京时间")
    print(f"来源健康 {len(source['nodes'])}/{source.get('total', len(source['nodes']))}  |  "
          f"目标健康 {len(target['nodes'])}/{target.get('total', len(target['nodes']))}")
    if plan["issues"]:
        print(f"\n预检冲突（{len(plan['issues'])}）")
        for issue in plan["issues"]:
            print(f"  {issue}")
        show_history(source, target)
        return

    creates, deletes = plan["creates"], plan["deletes"]
    adjustments = [item for item in plan["balances"] if item["change"]]
    print(f"同端口 {len(plan['matched'])}  |  新增 {len(creates)}  |  "
          f"删除 {len(deletes)}  |  调整余额 {len(adjustments)}")
    if deletes:
        print(f"\n待删除（{len(deletes)}）  目标机独有，正式同步时需单独确认")
        print_table(("端口", "出口", "目标到期"), (
            (row["port"], outlet(row), beijing(row["expires"])) for row in deletes))
    if creates:
        print(f"\n待新增（{len(creates)}）  目标机将继承来源的到期时间和配额规则")
        if deletes:
            print(f"先建后删，目标预计最多有 {len(target['nodes']) + len(creates)} 个临时节点。")
        created_rows = []
        for row in creates:
            quota = row["quota"]
            left, total, reset = ("无配额", "-", "-")
            if quota:
                left, total, reset = gibibytes(quota["left"]), gibibytes(quota["total"]), beijing(quota["next"])
            created_rows.append((row["port"], outlet(row), left, total, beijing(row["expires"]), reset))
        print_table(("端口", "出口", "剩余 GiB", "总额 GiB", "到期", "下次重置"), created_rows)
    if adjustments:
        print(f"\n待调整余额（{len(adjustments)}）  已有节点保留目标原到期和配额规则")
        balance_rows = []
        for item in adjustments:
            src, dst = item["source"]["quota"], item["target"]["quota"]
            balance_rows.append((item["port"], gibibytes(dst["left"]), gibibytes(src["left"]),
                                 balance_change(dst["left"], src["left"]), gibibytes(dst["total"]),
                                 beijing(dst["next"])))
        print_table(("端口", "当前 GiB", "对齐至 GiB", "变化", "目标总额 GiB", "下次重置"), balance_rows)
    if plan["balances"]:
        print("正式同步会重新采样余额。")
    if plan["uncapped"]:
        print(f"同端口、两边均无配额：{len(plan['uncapped'])} 个，保持原样。")
    if plan["notes"] and not details:
        print(f"已有节点有 {len(plan['notes'])} 项到期或配额规则差异，保留目标设置。")
    if details:
        show_plan_details(plan, target)
    show_history(source, target)



def wire_bytes(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def read_wire(stream):
    data = stream.readline(MAX_INPUT + 1)
    if not data:
        return None
    require(len(data) <= MAX_INPUT and data.endswith(b"\n"), "SSH 数据帧不完整或过大")
    message = json.loads(data)
    require(isinstance(message, dict), "SSH 数据帧格式异常")
    return message


def send_wire(stream, message):
    data = wire_bytes(message)
    require(len(data) < MAX_INPUT, "SSH 数据帧过大")
    stream.write(data + b"\n")
    stream.flush()


def serve(factory=Native, check_root=True):
    reader, writer = sys.stdin.buffer, sys.stdout.buffer
    host = None
    role = None
    locked = False
    with contextlib.ExitStack() as locks:
        while True:
            stop = False
            try:
                request = read_wire(reader)
                if request is None:
                    return
                op = request["op"]
                if op == "hello":
                    require(host is None, "SSH 会话已初始化")
                    require(not check_root or os.geteuid() == 0, "VPS 需要 root SSH 权限")
                    protocol, new_role = request["protocol"], request["role"]
                    require(protocol in PROTOCOLS and new_role in ("source", "target"), "SSH 会话角色或协议无效")
                    host = factory(protocol, role=new_role)
                    role = new_role
                    data = dict(version=WIRE_VERSION, host=host.host, boot=host.boot)
                elif role == "source":
                    if op == "inventory":
                        data = host.inventory(request.get("history", False))
                    elif op == "one":
                        data = host.one(request["row"])
                    elif op == "absent":
                        port = integer(request["port"], "端口", 1, 65535)
                        data = host.absent(port, request["revision"])
                    else:
                        raise SyncError("来源会话只允许读取库存、余额与端口状态")
                else:
                    require(role == "target", "SSH 会话尚未初始化")
                    if op == "lock":
                        require(not locked, "SSH 会话已经拿到节点锁")
                        locks.enter_context(host.locked())
                        locked, data = True, None
                    elif op in ("inventory", "prepare", "journal"):
                        with contextlib.nullcontext() if locked else host.locked():
                            if op == "inventory":
                                data = host.inventory(request.get("history", False))
                            elif op == "journal":
                                data = host.load_recovery()
                            else:
                                data = []
                                for row in request["rows"]:
                                    try:
                                        name, _, _ = host.prepare_create(row)
                                        data.append(dict(port=row["port"], native=name))
                                    except (SyncError, OSError, ValueError, KeyError, TypeError,
                                            subprocess.TimeoutExpired) as exc:
                                        data.append(dict(port=row["port"], error=safe_error(exc)))
                    else:
                        require(locked, "调用需要原生节点锁")
                        with finish_current_port() as interrupted:
                            if op == "create":
                                data = host.create(request["source"], request["origin"])
                            elif op == "balance":
                                data = host.balance(request["target"], request["source"], request["origin"])
                            elif op == "delete":
                                data = host.delete(request["target"], request["origin"], request["sampled_at"])
                            elif op == "recover":
                                data = host.recover(request["record"], request["source"])
                            else:
                                raise SyncError("未知 SSH 会话操作")
                        stop = bool(interrupted)
                send_wire(writer, dict(ok=True, result=data))
            except (SyncError, OSError, TypeError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired) as exc:
                if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
                    return
                try:
                    send_wire(writer, dict(ok=False, error=safe_error(exc)))
                except (BrokenPipeError, ConnectionResetError):
                    return
            if stop:
                return


REMOTE_BOOT = r'''
import sys
stream = sys.stdin.buffer
size = int(stream.readline(20))
if not 0 < size <= 524288:
    raise SystemExit("Bad sync program size")
program = stream.read(size)
if len(program) != size:
    raise SystemExit("Incomplete sync program")
scope = {"__name__": "_hy2_vless_remote"}
exec(compile(program, "<node-sync>", "exec"), scope)
scope["serve"]()
'''


def ssh_address(text):
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", text):
        return text
    try:
        parsed = ipaddress.ip_address(text)
        require(isinstance(parsed, ipaddress.IPv6Address) and "%" not in text, "请输入 VPS 地址或 SSH 别名")
        return text
    except ValueError as exc:
        raise SyncError("请输入 VPS 地址或 SSH 别名") from exc


def ssh_client_path(configured=None):
    if configured:
        path = Path(configured).expanduser()
        require(path.is_absolute(), "SSH 客户端需要使用绝对路径")
    else:
        name = shutil.which("ssh.exe") if os.name == "nt" else shutil.which("ssh") or shutil.which("ssh.exe")
        path = Path(name).absolute() if name else None
    if os.name == "nt":
        windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        native = tuple(windows / directory / "OpenSSH" / "ssh.exe" for directory in ("Sysnative", "System32"))
        if path is None or path in native:
            # The Windows inbox OpenSSH is in the native system directory.
            path = next((candidate for candidate in native if candidate.is_file()), path)
        require(path is None or path.suffix.lower() == ".exe", "Windows 需要 OpenSSH 的 ssh.exe")
    require(path is not None, "本机需要 OpenSSH 客户端")
    require(path.is_file(), f"找不到本机 SSH 客户端：{path}")
    return str(path)


class Remote:
    def __init__(self, address, port, key, protocol, role, program, *, ssh_client=None):
        address = ssh_address(address)
        port = integer(port, "SSH 端口", 1, 65535)
        self.label = f"{role} {address}:{port}"
        try:
            ssh = ssh_client_path(ssh_client)
        except OSError as exc:
            raise SyncError(f"{self.label}：无法检查本机 SSH 客户端（{exc}）") from exc
        command = [ssh, "-T", "-a", "-x", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                   "-o", "ClearAllForwardings=yes", "-o", "ControlPath=none", "-o", "ConnectTimeout=15",
                   "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
        if key:
            key = Path(key).expanduser()
            try:
                require(key.is_file(), f"{self.label} 的 SSH 私钥文件不存在")
            except OSError as exc:
                raise SyncError(f"{self.label}：本机无法检查 SSH 私钥（{exc.strerror}）") from exc
            command += ["-o", "IdentitiesOnly=yes", "-i", str(key)]
        command += ["-p", str(port), f"root@{address}", "python3 -IB -X utf8 -u -c " + shlex.quote(REMOTE_BOOT)]
        try:
            self.process = subprocess.Popen(command, executable=ssh, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        except OSError as exc:
            raise SyncError(f"{self.label}：无法在本机启动 SSH 客户端 {ssh}（{exc}）") from exc
        try:
            try:
                self.process.stdin.write(str(len(program)).encode("ascii") + b"\n" + program)
                self.process.stdin.flush()
            except OSError as exc:
                raise SyncError(f"{self.label}：无法通过本机 SSH 发送同步程序（{exc}）") from exc
            self.ident = self.rpc("hello", protocol=protocol, role=role)
            require(self.ident["version"] == WIRE_VERSION, "SSH 会话版本不一致")
        except BaseException:
            self.close()
            raise

    def rpc(self, op, **fields):
        try:
            send_wire(self.process.stdin, dict(op=op, **fields))
            response = read_wire(self.process.stdout)
        except OSError as exc:
            raise SyncError(f"{self.label} 的 SSH 连接异常（{exc}）") from exc
        except ValueError as exc:
            raise SyncError(f"{self.label} 的 SSH 数据帧异常") from exc
        require(response is not None, f"{self.label} 的 SSH 连接已中断")
        require(response.get("ok") is True, f"{self.label} {response.get('error', '缺少响应')}")
        return response["result"]

    def close(self):
        with contextlib.suppress(OSError):
            self.process.stdin.close()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            # This only ends the local SSH transport. A remote operation in
            # progress can finish its current native operation or use recovery.
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def lock_target(source, target):
    require(source.ident["host"] != target.ident["host"] and source.ident["boot"] != target.ident["boot"],
            "两台 VPS 的主机标识必须不同")
    target.rpc("lock")


def get_plan(source, target, wg_map, history=False):
    source_rows = source.rpc("inventory", history=history)
    target_rows = target.rpc("inventory", history=history)
    plan = make_plan(source_rows, target_rows, wg_map)
    if not plan["issues"] and plan["creates"]:
        for result in target.rpc("prepare", rows=plan["creates"]):
            if result.get("error"):
                plan["issues"].append(f"端口 {result['port']} 无法用目标原生创建器转换，{result['error']}")
    return source_rows, target_rows, plan


def keyed_operations(plan):
    actions = [("create", row) for row in plan["creates"]]
    actions += [("balance", row) for row in plan["balances"]]
    actions += [("delete", row) for row in plan["deletes"]]
    return actions


def run_operation(source, target, source_inventory, kind, row):
    origin = source_inventory["host"]
    if kind == "delete":
        sampled_at = source.rpc("absent", port=row["port"], revision=source_inventory["source_revision"])
        return target.rpc("delete", target=row, origin=origin, sampled_at=sampled_at)
    reference = row["source"] if kind == "balance" else row
    live = source.rpc("one", row=reference)
    if kind == "create":
        if "target_wg" in row:
            live["target_wg"] = row["target_wg"]
        if live["quota"] and row["quota"]["left"] != live["quota"]["left"]:
            print(f"端口 {row['port']} 来源余额已变化，继承最新 {live['quota']['left']} B")
        return target.rpc("create", source=live, origin=origin)
    if row["source"]["quota"]["left"] != live["quota"]["left"]:
        print(f"端口 {row['port']} 来源余额已变化，采用最新 {live['quota']['left']} B")
    return target.rpc("balance", target=row["target"], source=live, origin=origin)


def report_result(row, *, details=False):
    action, port = row["action"], row["port"]
    if action == "create":
        print(f"成功  创建 {port}  {outlet(row)}  到期 {beijing(row['expires'])}")
        print(f"      在目标 root 终端获取链接：{row['link_command']}")
    elif action == "balance":
        if details:
            print(f"成功  {port}  余额 {row['before']} B → {row['wanted']} B  核验 {row['actual']} B")
        else:
            print(f"成功  {port}  余额已核验：{gibibytes(row['actual'])} GiB")
    elif action == "delete":
        print(f"成功  原生删除 {port}")
    else:
        print(f"跳过  {port} {row['message']}")


def verify_final(source, target, before_target, outcomes, *, details=False):
    a, b, old = port_map(source), port_map(target), port_map(before_target)
    issues = source["issues"] + target["issues"]
    if set(a) != set(b):
        issues.append("端口集合仍有差异，目标缺失 " + ports_text(set(a) - set(b)) +
                      "，目标独有 " + ports_text(set(b) - set(a)))
    for p in sorted(set(a) & set(b)):
        if p in old and stable(b[p]) != stable(old[p]):
            issues.append(f"端口 {p} 的目标身份、到期或配额计划与执行前不同")
    for result in outcomes:
        port, kind = result["port"], result["action"]
        if kind in ("create", "balance") and port in b:
            q = b[port]["quota"]
            ceiling = result["wanted"] if kind == "balance" else (
                result["quota"]["stored"] if result["quota"] else None)
            if ceiling is not None and (q is None or q["left"] > ceiling):
                issues.append(f"端口 {port} 复审余额高于本轮设置值")
            if details and q:
                print(f"复审  {port} 实时 {q['left']} B、下期总额 {q['total']} B、重置 {beijing(q['next'])}")
        if kind == "create" and port in b and port in a:
            inherited = ("port", "expires", "landing", "family", "ip_limit", "sticky")
            if (any(b[port][k] != a[port][k] for k in inherited)
                    or schedule(b[port]["quota"]) != schedule(a[port]["quota"])):
                issues.append(f"端口 {port} 复审时的继承配置已变化")
    return issues


def execute(source, target, original_source, initial, wg_map, *, details=False):
    lock_target(source, target)
    before_source, before_target, current = get_plan(source, target, wg_map)
    if current["issues"]:
        show_plan(before_source, before_target, current, details=details)
        raise SyncError("加锁复检未通过，本轮尚未写入")
    require(before_source["source_revision"] == original_source["source_revision"]
            and plan_signature(initial) == plan_signature(current), "确认后节点或配额计划有变化，请重新对账")
    operations = keyed_operations(current)
    outcomes = []
    failed = False
    for port in current["uncapped"]:
        print(f"跳过  {port} 两端均无配额")
    for idx, (kind, row) in enumerate(operations):
        port = row["port"]
        try:
            if kind == "delete" and (idx == 0 or operations[idx - 1][0] != "delete"):
                source_again = source.rpc("inventory")
                require(not source_again["issues"]
                        and source_again["source_revision"] == before_source["source_revision"],
                        "删除前来源审计异常或节点清单变化")
            result = run_operation(source, target, before_source, kind, row)
            outcomes.append(result)
            report_result(result, details=details)
        except (SyncError, OSError) as exc:
            print(f"失败  {port} {exc}", file=sys.stderr)
            for later_kind, later in operations[idx + 1:]:
                print(f"未执行  {later['port']} {later_kind}")
            failed = True
            break
    print("\n重新审计两端")
    try:
        a, b = source.rpc("inventory"), target.rpc("inventory")
        issues = verify_final(a, b, before_target, outcomes, details=details)
        if a["source_revision"] != before_source["source_revision"]:
            issues.append("来源节点清单在执行中变化，请重新对账")
        for detail in issues:
            print(f"复审冲突  {detail}", file=sys.stderr)
        failed = failed or bool(issues)
        print(f"复审读取来源 {len(a['nodes'])} 个节点，目标 {len(b['nodes'])} 个节点")
    except (SyncError, OSError) as exc:
        print(f"复审失败  {exc}", file=sys.stderr)
        failed = True
    print("同步需要核对或恢复" if failed else "同步完成，端口集合和业务状态已复审")
    return 1 if failed else 0


def recover_run(source, target, ask):
    pending = target.rpc("journal")
    token = f"RECOVER {pending['port']}"
    print(f"目标待恢复端口 {pending['port']}，原操作 {pending['action']}，标签 {pending['tag']}")
    require(ask(f"请输入 {token} 确认处理本轮中断操作：").strip() == token, "已取消恢复")
    lock_target(source, target)
    data = source.rpc("inventory")
    require(not data["issues"], "来源预检异常，先核对来源")
    if pending["action"] == "delete":
        data["sampled_at"] = source.rpc("absent", port=pending["port"], revision=data["source_revision"])
    result = target.rpc("recover", record=pending, source=data)
    print(f"恢复  {result['port']} {result['message']}")
    final = target.rpc("inventory")
    for problem in final["issues"]:
        print(f"复审冲突  {problem}", file=sys.stderr)
    return 1 if final["issues"] else 0


def synchronize(source, target, *, apply=False, recover=False, history=False, details=False, wg_map=None, ask=input):
    wg_map = wg_map or {}
    if recover:
        return recover_run(source, target, ask)
    a, b, plan = get_plan(source, target, wg_map, history)
    show_plan(a, b, plan, details=details)
    if plan["issues"]:
        print("预检存在冲突，本轮尚未写入")
        return 1
    if not apply:
        print("\n只读对账完成，未修改节点。")
        return 0
    if not keyed_operations(plan):
        print("端口集合和无配额节点已对齐")
        return 0
    require(ask("请输入 APPLY 确认执行本轮同步：").strip() == "APPLY", "已取消修改")
    if plan["deletes"]:
        token = f"DELETE {len(plan['deletes'])}"
        print("待从目标机删除的端口：")
        print(textwrap.fill(ports_text(row["port"] for row in plan["deletes"]),
                            width=76, initial_indent="  ", subsequent_indent="  "))
        require(ask(f"请输入 {token} 确认删除：").strip() == token, "已取消删除，本轮尚未写入")
    return execute(source, target, a, plan, wg_map, details=details)


def parse_wg_mapping(values):
    mapping = {}
    for value in values:
        a, sep, b = value.partition("=")
        require(sep, "WireGuard 映射格式为 来源接口=目标接口")
        a, b = wg_interface(a), wg_interface(b)
        require(a not in mapping, "WireGuard 映射包含重复来源接口")
        mapping[a] = b
    return mapping


def main(argv=None):
    parser = argparse.ArgumentParser(description="HY2 ↔ VLESS 双向、按端口的临时节点镜像")
    parser.add_argument("--source-protocol", choices=PROTOCOLS)
    parser.add_argument("--source", help="来源 VPS 地址")
    parser.add_argument("--target", help="目标 VPS 地址")
    parser.add_argument("--source-port", type=int)
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--key", help="两端使用的 SSH 私钥路径")
    parser.add_argument("--source-key", help="来源 VPS 私钥路径")
    parser.add_argument("--target-key", help="目标 VPS 私钥路径")
    parser.add_argument("--ssh-client", help="本机 OpenSSH 客户端的绝对路径")
    parser.add_argument("--wg-map", action="append", default=[], help="来源接口=目标接口，可多次指定")
    parser.add_argument("--history", action="store_true", help="显示已有的每日流量")
    parser.add_argument("--details", action="store_true", help="显示精确字节数和节点参数")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true", help="预检及明确确认后执行")
    modes.add_argument("--compare", action="store_true", help="只读对账（默认）")
    modes.add_argument("--recover", action="store_true", help="处理同一目标上的中断记录")
    args = parser.parse_args(argv)
    try:
        protocol = args.source_protocol or input("来源协议 hy2 / vless：").strip().lower()
        require(protocol in PROTOCOLS, "来源协议应为 hy2 或 vless")
        other = "vless" if protocol == "hy2" else "hy2"
        source = args.source or input(f"来源 {protocol.upper()} VPS 地址：").strip()
        target = args.target or input(f"目标 {other.upper()} VPS 地址：").strip()
        source_port = args.source_port if args.source_port is not None else (
            input("来源 SSH 端口 [22]：").strip() or 22 if not args.source else 22)
        target_port = args.target_port if args.target_port is not None else (
            input("目标 SSH 端口 [22]：").strip() or 22 if not args.target else 22)
        common_key = args.key
        default_key = Path.home() / ".ssh" / "vps_root_ed25519"
        try:
            if not common_key and default_key.is_file():
                common_key = default_key
        except OSError as exc:
            raise SyncError(f"无法检查本机默认 SSH 私钥（{exc.strerror}）") from exc
        try:
            program = Path(__file__).read_bytes()
        except OSError as exc:
            raise SyncError(f"无法读取本机同步程序（{exc}）") from exc
        require(len(program) <= MAX_PROGRAM, "本机程序超出 SSH 传输大小")
        wg_map = parse_wg_mapping(args.wg_map)
        with Remote(source, source_port, args.source_key or common_key, protocol, "source", program,
                    ssh_client=args.ssh_client) as a, \
             Remote(target, target_port, args.target_key or common_key, other, "target", program,
                    ssh_client=args.ssh_client) as b:
            return synchronize(a, b, apply=args.apply, recover=args.recover, history=args.history,
                               details=args.details, wg_map=wg_map)
    except (SyncError, OSError, EOFError) as exc:
        print(f"操作停止  {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n操作中断，重新预检可查看目标是否有待恢复记录。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

