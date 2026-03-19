import asyncio
import ipaddress
import os
import random
import ssl
import time
import urllib.request
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


async def probe_http(ip: str, port: int, server_name: str, timeout: float) -> float | None:
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
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {server_name}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        writer.write(req)
        await writer.drain()
        first = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not first.startswith(b"HTTP/1.1 ") and not first.startswith(b"HTTP/2 "):
            return None
        try:
            status = int(first.split()[1])
        except Exception:
            return None
        if status >= 500:
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


async def run() -> None:
    target_host = read_env("TARGET_HOST", "qq.mingvpn.dpdns.org")

    ports_raw = read_env("PORTS", "443,2053,2083,2087,2096,8443")
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
        sample_ips = int(read_env("SAMPLE_IPS", "600"))
    except ValueError:
        sample_ips = 600
    try:
        output_limit = int(read_env("OUTPUT_LIMIT", "80"))
    except ValueError:
        output_limit = 80
    try:
        concurrency = int(read_env("CONCURRENCY", "250"))
    except ValueError:
        concurrency = 250
    try:
        timeout_sec = float(read_env("TIMEOUT_SEC", "2.5"))
    except ValueError:
        timeout_sec = 2.5
    try:
        max_ms = float(read_env("MAX_MS", "180"))
    except ValueError:
        max_ms = 180
    try:
        max_per_prefix = int(read_env("MAX_PER_PREFIX", "3"))
    except ValueError:
        max_per_prefix = 3

    sample_ips = max(1, sample_ips)
    output_limit = max(1, output_limit)
    concurrency = max(1, min(concurrency, sample_ips))
    timeout_sec = max(0.2, timeout_sec)
    max_ms = max(1.0, max_ms)
    max_per_prefix = max(1, max_per_prefix)

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
            ms = await probe_http(ip, port, target_host, timeout_sec)
            return (ip, port, ms)

    results = await asyncio.gather(*(one(ip, port) for ip, port in candidates))

    ok = [(ip, port, ms) for ip, port, ms in results if ms is not None and ms <= max_ms]
    ok.sort(key=lambda x: x[2])

    picked = []
    prefix_count: dict[str, int] = {}
    for ip, port, ms in ok:
        prefix = ".".join(ip.split(".")[:2])
        count = prefix_count.get(prefix, 0)
        if count >= max_per_prefix:
            continue
        picked.append((ip, port, ms))
        prefix_count[prefix] = count + 1
        if len(picked) >= output_limit:
            break

    top = picked
    lines = [f"{ip}:{port}#{int(ms)}ms" for ip, port, ms in top]
    content = "\n".join(lines).strip() + ("\n" if lines else "")

    Path("ip.txt").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(run())
