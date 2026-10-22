"""Build one PROXY rule set; unmatched traffic must use DIRECT."""

import hashlib
import json
import pathlib
import subprocess
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = "ghcr.io/sagernet/sing-box:v1.14.2"

SOURCES = [
    (
        "geosite-cn",
        "SagerNet/sing-geosite",
        "50375ffe2f3a40cad8ce2ecf6c37afcbb7e01984",
        "e1442916bbb370dc46905ebb1700c75f3be4bc5311c708543b8a5dfc90f7b9d4",
    ),
    (
        "geoip-cn",
        "SagerNet/sing-geoip",
        "eb32cd6ed4a16fcb3bf9a36ccebf28e45716ae84",
        "81ada5cafd9d831adc48776f29cdfe55c9713d9287caeef9de925ef30f66cce4",
    ),
]


def sing_box(*args):
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/work",
            "-w",
            "/work",
            IMAGE,
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def build():
    cache = ROOT / ".build"
    cache.mkdir(exist_ok=True)
    cn_rules = []

    for tag, repo, revision, digest in SOURCES:
        url = (
            "https://raw.githubusercontent.com/"
            f"{repo}/{revision}/{tag}.srs"
        )
        data = urllib.request.urlopen(
            url,
            timeout=60,
        ).read()

        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != digest:
            raise ValueError(f"{tag}: checksum mismatch")

        (cache / f"{tag}.srs").write_bytes(data)

        sing_box(
            "rule-set",
            "decompile",
            "--output",
            f".build/{tag}.json",
            f".build/{tag}.srs",
        )

        source_text = (
            cache / f"{tag}.json"
        ).read_text(encoding="utf-8")

        rules = json.loads(source_text)["rules"]

        if not rules:
            raise ValueError(f"{tag}: empty rule source")

        cn_rules.extend(rules)

    priority = [
        "openai.com",
        "chatgpt.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "workos.com",
        "github.com",
        "githubusercontent.com",
        "githubassets.com",
        "anthropic.com",
        "claude.ai",
        "huggingface.co",
        "replicate.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "youtube.com",
        "ytimg.com",
        "googlevideo.com",
        "npmjs.org",
        "npmjs.com",
        "pypi.org",
        "pythonhosted.org",
        "docker.com",
        "docker.io",
        "telegram.org",
        "t.me",
        "x.com",
        "twitter.com",
        "twimg.com",
        "facebook.com",
        "instagram.com",
        "threads.net",
    ]

    private = [
        "47.91.94.67/32",
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]

    priority_suffixes = []
    for domain in priority:
        priority_suffixes.extend([
            domain,
            "." + domain,
        ])

    excluded = {
        "type": "logical",
        "mode": "or",
        "invert": True,
        "rules": [
            {
                "ip_cidr": private,
            },
            {
                "domain_suffix": [
                    "localhost",
                    ".localhost",
                    ".local",
                    ".lan",
                    ".home.arpa",
                ],
                "domain_regex": [
                    "^[^.]+$",
                ],
            },
        ],
    }

    overseas = {
        "type": "logical",
        "mode": "or",
        "rules": [
            {
                "domain_suffix": priority_suffixes,
            },
            {
                "type": "logical",
                "mode": "or",
                "invert": True,
                "rules": cn_rules,
            },
        ],
    }

    result = {
        "version": 1,
        "rules": [
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    excluded,
                    overseas,
                ],
            },
        ],
    }

    output_text = json.dumps(
        result,
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    (ROOT / "bobo-final-proxy.json").write_text(
        output_text,
        encoding="utf-8",
    )

    sing_box(
        "rule-set",
        "compile",
        "--output",
        "bobo-final-proxy.srs",
        "bobo-final-proxy.json",
    )

    verify()


def verify():
    proxy = [
        "chatgpt.com",
        "chatgpt.com.cdn.cloudflare.net",
        "api.openai.com",
        "auth.openai.com",
        "cdn.oaistatic.com",
        "files.oaiusercontent.com",
        "api.workos.com",
        "github.com",
        "raw.githubusercontent.com",
        "claude.ai",
        "google.com",
        "youtube.com",
        "example.org",
        "unlisted-overseas-example.net",
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
    ]

    direct = [
        "baidu.com",
        "www.qq.com",
        "taobao.com",
        "jd.com",
        "bilibili.com",
        "www.gov.cn",
        "unlisted-domestic-example.cn",
        "localhost",
        "router.local",
        "nas.lan",
        "printer",
        "47.91.94.67",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.1.1",
        "100.64.0.1",
        "127.0.0.1",
        "223.5.5.5",
        "114.114.114.114",
        "::1",
        "fd00::1",
        "fe80::1",
    ]

    evidence = []

    for expected, targets in [
        (True, proxy),
        (False, direct),
    ]:
        for target in targets:
            completed = sing_box(
                "rule-set",
                "match",
                "--format",
                "binary",
                "bobo-final-proxy.srs",
                target,
            )

            output = completed.stdout + completed.stderr
            matched = "match rules.[" in output

            if matched != expected:
                raise AssertionError(
                    f"{target}: expected proxy={expected}, "
                    f"actual={matched}"
                )

            evidence.append({
                "target": target,
                "proxy": matched,
                "pass": True,
            })

    report = {
        "compiler": IMAGE,
        "sources": SOURCES,
        "checks": evidence,
        "scope": (
            "Binary rule matching only; "
            "phone routing, DNS and live sessions "
            "are not verified."
        ),
    }

    (ROOT / "verification.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"PASS: {len(evidence)} "
        "native binary matching checks"
    )


if __name__ == "__main__":
    build()