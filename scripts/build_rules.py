"""Single PROXY rule set; the phone must send unmatched traffic to DIRECT.

Drop-in replacement for scripts/build_rules.py. Python standard library only;
Docker and its running daemon are still external requirements. Candidate checks
are not phone DNS, default-route, FakeIP or long-term stability verification.
Publication rolls back ordinary exceptions; three files are NOT crash-atomic.
"""
import contextlib
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = "ghcr.io/sagernet/sing-box:v1.14.2"
COMMAND_TIMEOUT = 300
SOURCES = [
    ("geosite-cn", "SagerNet/sing-geosite", "50375ffe2f3a40cad8ce2ecf6c37afcbb7e01984",
     "e1442916bbb370dc46905ebb1700c75f3be4bc5311c708543b8a5dfc90f7b9d4"),
    ("geoip-cn", "SagerNet/sing-geoip", "eb32cd6ed4a16fcb3bf9a36ccebf28e45716ae84",
     "81ada5cafd9d831adc48776f29cdfe55c9713d9287caeef9de925ef30f66cce4"),
]
PRIORITY = [
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "workos.com",
    "github.com", "githubusercontent.com", "githubassets.com", "anthropic.com",
    "claude.ai", "huggingface.co", "replicate.com", "google.com", "googleapis.com",
    "gstatic.com", "googleusercontent.com", "youtube.com", "ytimg.com", "googlevideo.com",
    "npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org", "docker.com", "docker.io",
    "telegram.org", "t.me", "x.com", "twitter.com", "twimg.com", "facebook.com",
    "instagram.com", "threads.net",
]
PRIVATE = [
    "47.91.94.67/32", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128",
    "fc00::/7", "fe80::/10", "ff00::/8",
]
PROXY_CASES = [
    "chatgpt.com", "chatgpt.com.cdn.cloudflare.net", "api.openai.com", "auth.openai.com",
    "cdn.oaistatic.com", "files.oaiusercontent.com", "api.workos.com", "github.com",
    "raw.githubusercontent.com", "claude.ai", "google.com", "youtube.com", "example.org",
    "unlisted-overseas-example.net", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111",
    "dit.whatsapp.net",
]
DIRECT_CASES = [
    "baidu.com", "www.qq.com", "taobao.com", "jd.com", "bilibili.com", "www.gov.cn",
    "unlisted-domestic-example.cn", "localhost", "router.local", "nas.lan", "printer",
    "47.91.94.67", "192.168.1.1", "10.0.0.1", "172.16.1.1", "100.64.0.1",
    "127.0.0.1", "223.5.5.5", "114.114.114.114", "::1", "fd00::1", "fe80::1",
    "douyin.com", "weixin.qq.com", "alipay.com",
]
OUTPUT_NAMES = ("bobo-final-proxy.json", "bobo-final-proxy.srs", "verification.json")


def log(stage, message):
    print(f"[{stage}] {message}", flush=True)


def work_path(path):
    return path.relative_to(ROOT).as_posix()


@contextlib.contextmanager
def build_lock(cache):
    lock = cache / "build.lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise RuntimeError(
            f"Build lock exists: {lock}. Another build may be running. "
            "If a previous process crashed, first confirm no build is active, "
            "then manually remove this lock directory; it is never stolen automatically."
        ) from exc
    try:
        write_json(lock / "owner.json", {"pid": os.getpid(), "started_unix": time.time()})
        yield
    finally:
        shutil.rmtree(lock)


def sing_box(*args):
    command = ["docker", "run", "--rm", "-v", f"{ROOT}:/work", "-w", "/work", IMAGE, *args]
    log("docker", " ".join(args))
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=COMMAND_TIMEOUT)
    except FileNotFoundError as exc:
        raise RuntimeError("Docker executable not found; publication stopped") from exc
    except subprocess.TimeoutExpired as exc:
        log("docker-timeout", f"Exceeded {COMMAND_TIMEOUT}s: {' '.join(args)}")
        if exc.stdout:
            print(exc.stdout, flush=True)
        if exc.stderr:
            print(exc.stderr, flush=True)
        raise RuntimeError(
            "Docker CLI timed out; publication stopped. The container may still be running; "
            "this timeout does not prove container cleanup."
        ) from exc
    if completed.returncode:
        log("docker-failed", f"exit={completed.returncode}: {' '.join(args)}")
        print(completed.stdout, flush=True)
        print(completed.stderr, flush=True)
        raise RuntimeError(f"sing-box exited with code {completed.returncode}")
    return completed.stdout + completed.stderr


def download(url, tag):
    for attempt in range(3):
        log("download", f"{tag}: attempt={attempt + 1}/3 url={url}")
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "bobo-rules-builder/2.3.1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(32 * 1024 * 1024 + 1)
            if not data or len(data) > 32 * 1024 * 1024:
                raise ValueError(f"{tag}: download empty or exceeds 32 MiB: {url}")
            return data
        except urllib.error.HTTPError as exc:
            log("download-error", f"{tag}: HTTP {exc.code} url={url}")
            if exc.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            log("download-error", f"{tag}: {type(exc).__name__}: {exc}; url={url}")
            if attempt == 2:
                raise
        time.sleep(2 ** (attempt + 1))
    raise RuntimeError(f"{tag}: download failed: {url}")


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def check_digest(data, expected, tag):
    actual = hashlib.sha256(data).hexdigest()
    log("sha256", f"{tag}: expected={expected} actual={actual}")
    if actual != expected:
        raise ValueError(f"{tag}: SHA-256 mismatch; publication stopped")


def source_rules(source, tag):
    if not isinstance(source, dict):
        raise ValueError(f"{tag}: decompiled JSON must be an object")
    # Check structure only; the pinned compiler validates full format semantics.
    version = source.get("version")
    if type(version) is not int or version < 1:
        raise ValueError(f"{tag}: invalid decompiled rule-set version: {version!r}")
    rules = source.get("rules")
    if not isinstance(rules, list) or not rules or not all(isinstance(r, dict) and r for r in rules):
        raise ValueError(f"{tag}: invalid or empty rules; publication stopped")
    return rules


def make_rules(cn_rules):
    suffixes = sorted({item for domain in PRIORITY for item in (domain, "." + domain)})
    return {"version": 1, "rules": [{"type": "logical", "mode": "and", "rules": [
        {"type": "logical", "mode": "or", "invert": True, "rules": [
            {"ip_cidr": PRIVATE},
            {"domain_suffix": ["localhost", ".localhost", ".local", ".lan", ".home.arpa"],
             "domain_regex": ["^[^.]+$"]},
        ]},
        {"type": "logical", "mode": "or", "rules": [
            {"domain_suffix": suffixes},
            {"type": "logical", "mode": "or", "invert": True, "rules": cn_rules},
        ]},
    ]}]}


def verify(binary_path):
    evidence, failures = [], []
    for expected, targets in [(True, PROXY_CASES), (False, DIRECT_CASES)]:
        for target in targets:
            output = sing_box("rule-set", "match", "--format", "binary", binary_path, target)
            matched = bool(re.search(r"match rules\.\[\s*\d+\s*\]", output))
            passed = matched == expected
            evidence.append({"target": target, "expected_proxy": expected,
                             "proxy": matched, "pass": passed})
            if not passed:
                failures.append(target)
                log("match-failed", f"{target}: expected_proxy={expected} actual={matched}")
                print(output, flush=True)
    if failures:
        raise RuntimeError("Matching checks failed: " + ", ".join(failures))
    log("match", f"PASS: {len(evidence)} native binary matching checks")
    return evidence


class PublicationRecoveryError(RuntimeError):
    """Keep the staging directory for manual recovery."""


def publish(candidates, staging):
    """Rollback ordinary exceptions. Not an atomic transaction across files."""
    backup = staging / "publication-backup"
    backup.mkdir()
    existed = {}
    for name in OUTPUT_NAMES:
        destination = ROOT / name
        if destination.is_symlink() or (destination.exists() and not destination.is_file()):
            raise ValueError(f"Refusing non-regular publication target: {destination}")
        existed[name] = destination.exists()
        if existed[name]:
            shutil.copy2(destination, backup / name)
    replaced = []
    try:
        for name in OUTPUT_NAMES:
            candidates[name].replace(ROOT / name)
            replaced.append(name)
    except Exception as exc:
        rollback_errors = []
        for name in reversed(replaced):
            try:
                if existed[name]:
                    restore = staging / ("restore-" + name)
                    shutil.copy2(backup / name, restore)
                    restore.replace(ROOT / name)
                else:
                    (ROOT / name).unlink()
                log("rollback", f"Restored prior state: {name}")
            except Exception as rollback_exc:
                rollback_errors.append(f"{name}: {rollback_exc}")
                log("rollback-failed", rollback_errors[-1])
        if rollback_errors:
            log("recovery", f"Keep backups for manual recovery at {backup}")
            raise PublicationRecoveryError(
                "Publication AND rollback failed; backups retained at " + str(backup)
                + ": " + "; ".join(rollback_errors)
            ) from exc
        raise RuntimeError("Publication failed; prior output states restored") from exc


def build():
    cache = ROOT / ".build"
    cache.mkdir(exist_ok=True)
    with build_lock(cache):
        staging = pathlib.Path(tempfile.mkdtemp(prefix="rules-", dir=cache))
        keep_staging = False
        try:
            cn_rules = []
            for tag, repo, revision, digest in SOURCES:
                url = f"https://raw.githubusercontent.com/{repo}/{revision}/{tag}.srs"
                log("source", f"{tag}: repo={repo} revision={revision}")
                data = download(url, tag)
                check_digest(data, digest, tag)
                binary, decoded = staging / f"{tag}.srs", staging / f"{tag}.json"
                binary.write_bytes(data)
                sing_box("rule-set", "decompile", "--output", work_path(decoded), work_path(binary))
                try:
                    source = json.loads(decoded.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise ValueError(f"{tag}: cannot read decompiled JSON: {decoded}: {exc}") from exc
                cn_rules.extend(source_rules(source, tag))
            candidate_json, candidate_srs = staging / "candidate.json", staging / "candidate.srs"
            write_json(candidate_json, make_rules(cn_rules))
            sing_box("rule-set", "compile", "--output", work_path(candidate_srs), work_path(candidate_json))
            if not candidate_srs.is_file() or candidate_srs.stat().st_size == 0:
                raise ValueError("Compiler produced no usable binary; publication stopped")
            with candidate_srs.open("rb") as binary_file:
                if binary_file.read(4) != b"SRS\x01":
                    raise ValueError("Unexpected binary header; expected SRS format version 1")
            checks = verify(work_path(candidate_srs))
            report = {
                "builder_version": "2.3.1", "compiler": IMAGE, "sources": SOURCES,
                "binary_format_version": 1,
                "sha256": hashlib.sha256(candidate_srs.read_bytes()).hexdigest(), "checks": checks,
                "scope": "Binary matching only; phone DNS, default route and live sessions are not verified.",
            }
            candidate_report = staging / "verification.json"
            write_json(candidate_report, report)
            publish(dict(zip(OUTPUT_NAMES, (candidate_json, candidate_srs, candidate_report))), staging)
            log("publish", "Verified artifacts ready for the existing workflow to commit.")
        except PublicationRecoveryError:
            keep_staging = True
            raise
        finally:
            if not keep_staging:
                shutil.rmtree(staging)



if __name__ == "__main__":
    build()
