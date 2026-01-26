import os
import random
import re
import urllib.request
from pathlib import Path


def _download_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


def _extract_ipv4(text: str) -> list[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def _normalize_items(ips: list[str], port: str) -> list[str]:
    uniq = []
    seen = set()
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        uniq.append(f"{ip}:{port}")
    return uniq


def main() -> None:
    source_url = (os.getenv("IPS_SOURCE_URL") or "").strip()
    output_port = (os.getenv("OUTPUT_PORT") or "443").strip()
    output_limit = int((os.getenv("OUTPUT_LIMIT") or "80").strip())

    ips: list[str] = []
    if source_url:
        text = _download_text(source_url)
        ips = _extract_ipv4(text)

    if not ips:
        existing = Path("ip.txt")
        if existing.exists():
            raw = existing.read_text(encoding="utf-8", errors="replace")
            ips = _extract_ipv4(raw)

    if not ips:
        raise SystemExit("No IPs found. Set IPS_SOURCE_URL or put some IPs into ip.txt first.")

    items = _normalize_items(ips, output_port)
    random.shuffle(items)
    items = items[:output_limit]

    content = "\n".join(items).strip() + "\n"
    Path("ip.txt").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
