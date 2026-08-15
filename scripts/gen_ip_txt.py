import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import random
import ssl
import time
import urllib.request
from functools import lru_cache
from pathlib import Path

def read_env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v is not None and str(v).strip() else default

def fetch_lines(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]

def pick_random_ipv4_from_cidr(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses <= 2:
        return str(net.network_address)
    start = int(net.network_address) + 1
    end = int(net.broadcast_address) - 1
    return str(ipaddress.IPv4Address(random.randint(start, end)))

async def probe_tls(ip: str, port: int, server_name: str, timeout: float) -> float | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_name),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (time.perf_counter() - start) * 1000.0
    except Exception:
        return None

async def probe_websocket(ip: str, port: int, server_name: str, ws_path: str, timeout: float) -> float | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    start = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_name),
            timeout=timeout,
        )
        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {server_name}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("utf-8")
        writer.write(req)
        await writer.drain()
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        first, *rest = header.split(b"\r\n")
        if not first.startswith(b"HTTP/1.1 101"):
            return None
        headers = {}
        for line in rest:
            if not line or b":" not in line:
                continue
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip().lower()
        if headers.get(b"upgrade") != b"websocket":
            return None
        accept = headers.get(b"sec-websocket-accept")
        if not accept:
            return None
        expected = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")).digest()
        ).decode("ascii").lower().encode("ascii")
        if accept != expected:
            return None
        return (time.perf_counter() - start) * 1000.0
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

COUNTRY_CN = {
    "US": "美国",
    "HK": "香港",
    "JP": "日本",
    "SG": "新加坡",
    "KR": "韩国",
    "TW": "台湾",
    "CN": "中国",
    "CA": "加拿大",
    "GB": "英国",
    "DE": "德国",
    "FR": "法国",
    "NL": "荷兰",
    "AU": "澳大利亚",
    "IN": "印度",
    "BR": "巴西",
    "RU": "俄罗斯",
    "ID": "印尼",
    "TH": "泰国",
    "MY": "马来西亚",
    "VN": "越南",
    "PH": "菲律宾",
    "AE": "阿联酋",
    "CH": "瑞士",
    "SE": "瑞典",
    "FI": "芬兰",
    "PL": "波兰",
    "IT": "意大利",
    "ES": "西班牙",
    "TR": "土耳其",
    "AR": "阿根廷",
    "MX": "墨西哥",
    "NZ": "新西兰",
    "SA": "沙特阿拉伯",
    "ZA": "南非",
}

@lru_cache(maxsize=4096)
def get_location_cn(ip: str) -> tuple[str, str]:
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        code = (data.get("country_code") or "").upper()
        country = COUNTRY_CN.get(code) or data.get("country_name") or "未知国家"
        city = data.get("city") or ""
        return country, city
    except Exception:
        return "未知国家", ""

async def run() -> None:
    target_host = read_env("TARGET_HOST", "qq.mingvpn.dpdns.org")

    ports_raw = read_env("PORTS", "443,8443,2053")
    ports = []
    for p in ports_raw.replace(" ", "").split(","):
        if not p:
            continue
        try:
            ports.append(int(p))
        except ValueError:
            pass
    if not ports:
        raise SystemExit("No valid PORTS")

    try:
        sample_ips = int(read_env("SAMPLE_IPS", "800"))
    except ValueError:
        sample_ips = 800
    try:
        output_limit = int(read_env("OUTPUT_LIMIT", "20"))
    except ValueError:
        output_limit = 20
    try:
        concurrency = int(read_env("CONCURRENCY", "60"))
    except ValueError:
        concurrency = 60
    try:
        timeout_sec = float(read_env("TIMEOUT_SEC", "4"))
    except ValueError:
        timeout_sec = 4.0
    try:
        max_ms = float(read_env("MAX_MS", "350"))
    except ValueError:
        max_ms = 350.0
    try:
        max_per_prefix = int(read_env("MAX_PER_PREFIX", "3"))
    except ValueError:
        max_per_prefix = 3
    try:
        min_output = int(read_env("MIN_OUTPUT", "1"))
    except ValueError:
        min_output = 1
    ws_path = read_env("WS_PATH", "/")
    if not ws_path.startswith("/"):
        ws_path = "/" + ws_path

    sample_ips = max(1, sample_ips)
    output_limit = max(1, output_limit)
    concurrency = max(1, min(concurrency, sample_ips))
    timeout_sec = max(0.2, timeout_sec)
    max_ms = max(1.0, max_ms)
    max_per_prefix = max(1, max_per_prefix)
    min_output = max(1, min(min_output, output_limit))

    cidrs = fetch_lines("https://www.cloudflare.com/ips-v4")
    if not cidrs:
        raise SystemExit("Failed to fetch Cloudflare IPv4 ranges")

    candidates: list[tuple[str, int]] = []
    seen_candidates: set[tuple[str, int]] = set()
    while len(candidates) < sample_ips:
        cidr = random.choice(cidrs)
        ip = pick_random_ipv4_from_cidr(cidr)
        port = random.choice(ports)
        key = (ip, port)
        if key in seen_candidates:
            continue
        seen_candidates.add(key)
        candidates.append(key)

    sem = asyncio.Semaphore(concurrency)

    async def one(ip: str, port: int):
        async with sem:
            tls_ms = await probe_tls(ip, port, target_host, timeout_sec)
            if tls_ms is None:
                return (ip, port, None)
            ms = await probe_websocket(ip, port, target_host, ws_path, timeout_sec)
            return (ip, port, ms)

    results = await asyncio.gather(*(one(ip, port) for ip, port in candidates))

    ok = [(ip, port, ms) for ip, port, ms in results if ms is not None]

    def port_penalty(p: int) -> float:
        if p == 443:
            return 0.0
        if p == 8443:
            return 8.0
        return 20.0

    def pick(items: list[tuple[str, int, float]], limit_ms: float, per_prefix: int) -> list[tuple[str, int, float]]:
        within = [(ip, port, ms) for ip, port, ms in items if ms <= limit_ms]
        within.sort(key=lambda x: x[2] + port_penalty(x[1]))
        picked_local: list[tuple[str, int, float]] = []
        prefix_count: dict[str, int] = {}
        for ip, port, ms in within:
            prefix = ".".join(ip.split(".")[:2])
            count = prefix_count.get(prefix, 0)
            if count >= per_prefix:
                continue
            picked_local.append((ip, port, ms))
            prefix_count[prefix] = count + 1
            if len(picked_local) >= output_limit:
                break
        return picked_local

    top = pick(ok, max_ms, max_per_prefix)
    if len(top) < min_output:
        top = pick(ok, max_ms * 1.6, max_per_prefix + 1)
    if len(top) < min_output:
        top = pick(ok, max_ms * 2.2, max_per_prefix + 2)

    lines = []
    for ip, port, ms in top:
        country, city = get_location_cn(ip)
        location = f"{country}{city}".strip()
        if not location:
            location = "未知地区"
        lines.append(f"{ip}:{port}#{location} {int(ms)}ms")

    if not lines:
        raise SystemExit("No healthy endpoints found with current thresholds. Keep previous ip.txt and relax filters.")

    content = "\n".join(lines).strip() + ("\n" if lines else "")

    Path("ip.txt").write_text(content, encoding="utf-8")

if __name__ == "__main__":
    asyncio.run(run())
