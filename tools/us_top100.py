#!/usr/bin/env python3
# Build a US-egress-only Clash/Mihomo subscription from the configured Telegram crawl.
from __future__ import annotations

import base64
import json
import os
import re
import random
import statistics
import subprocess
import sys
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))

import executable
import location
import clash
import pipeline
import push
import utils
import workflow
import yaml
from config.models import ProcessConfig, YandexConfig, GithubConfig, NodeInput, SiteConfig
from crawl import engine as crawl_engine
from geoip2 import database
from location import ProxyInfo, ProxyQueryResult

ALLOWED_TYPES = {"http", "ss", "trojan", "vless"}  # Keep the four protocols prioritized for handset compatibility
MAX_CANDIDATES = 10000  # Public feeds plus configured crawlers; strict successful Mihomo checks only
BATCH_SIZE = 80
SPEED_BYTES = 524288
OUT = ROOT / "output"
WORKSPACE = ROOT / "clash"
TEST_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes={}"


def chunks(items, size):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def protocol_counts(nodes):
    counts = {}
    for node in nodes or []:
        kind = str(node.get("type", "unknown") if isinstance(node, dict) else "invalid").lower()
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def select_protocol_diverse(nodes, target=36, minimum_per_protocol=3):
    """Select only the four retained protocols and balance their final counts.

    First reserve a minimum quota for each protocol with enough validated
    candidates. Then repeatedly select from the currently least-represented
    protocol, using the measured global score to break ties.
    """
    priority = ["http", "ss", "trojan", "vless"]
    buckets = {}
    for node in nodes:
        kind = str(node.get("type", "unknown")).lower()
        if kind in ALLOWED_TYPES:
            buckets.setdefault(kind, []).append(node)

    # Incoming nodes are globally score-ranked; preserve that order per bucket.
    selected, selected_ids, quota = [], set(), {}
    for kind in priority:
        bucket = buckets.get(kind, [])
        if len(bucket) >= minimum_per_protocol:
            chosen = bucket[:minimum_per_protocol]
            selected.extend(chosen)
            selected_ids.update(id(item) for item in chosen)
            quota[kind] = len(chosen)

    # Balance by current count; among equally represented protocols, take
    # the best next measured candidate. Stop at the target or when exhausted.
    while len(selected) < target:
        choices = []
        for kind in priority:
            bucket = buckets.get(kind, [])
            next_node = next((item for item in bucket if id(item) not in selected_ids), None)
            if next_node is not None:
                choices.append((quota.get(kind, 0), -float(next_node.get("_score", 0)), priority.index(kind), kind, next_node))
        if not choices:
            break
        _, _, _, kind, node = min(choices)
        selected.append(node)
        selected_ids.add(id(node))
        quota[kind] = quota.get(kind, 0) + 1

    return selected, quota


def run_alive_check(nodes, clash_bin):
    alive = []
    for index, batch in enumerate(chunks(nodes, BATCH_SIZE), 1):
        print(f"[alive] batch {index}, candidates={len(batch)}", flush=True)
        filename = "us_top100_test.yaml"
        checked = clash.generate_config(str(WORKSPACE), batch, filename)
        binpath = WORKSPACE / clash_bin
        process = subprocess.Popen(
            [str(binpath), "-d", str(WORKSPACE), "-f", str(WORKSPACE / filename)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(7)
            params = [
                [item, clash.EXTERNAL_CONTROLLER, 15000, TEST_URL, 15000, False]
                for item in checked if isinstance(item, dict)
            ]
            masks = utils.multi_thread_run(
                func=clash.check,
                tasks=params,
                num_threads=32,
                show_progress=False,
                description="Mihomo connectivity checks",
            ) or []
            alive.extend([checked[i] for i in range(min(len(checked), len(masks))) if masks[i]])
        finally:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
    return alive


def _country_code(value):
    value = str(value or "").strip().upper()
    if value in ("美国", "UNITED STATES", "UNITED STATES OF AMERICA"):
        return "US"
    if len(value) == 2 and value.isalpha():
        return value
    return ""


def _geo_api_probe(proxy, port, reader=None):
    """Determine the actual proxy egress country without depending on a local MMDB."""
    name = str(proxy.get("name", ""))
    votes = []
    ip_seen = ""
    observed_ips = []
    # Each request is made through this node's Mihomo listener, never from the runner.
    endpoints = [
        ("https://ipwho.is/", "country_code"),
        ("https://ipapi.co/json/", "country_code"),
        ("https://ipinfo.io/json", "country"),
    ]
    for url, key in endpoints:
        try:
            ok, data = location.make_proxy_request(
                port=port, url=url, max_retries=1, timeout=10, quiet=True
            )
            if not ok or not isinstance(data, dict):
                continue
            if url.startswith("https://ipwho.is/") and data.get("success") is False:
                continue
            code = _country_code(data.get(key))
            if code:
                votes.append(code)
                observed_ip = str(data.get("ip", "")).strip()
                if observed_ip:
                    observed_ips.append(observed_ip)
                    ip_seen = ip_seen or observed_ip
        except Exception as exc:
            print(f"[geoip-api] {name} {url} failed: {exc}", flush=True)

    # Require independent providers to agree on both country and exact egress IP.
    if len(votes) < 2 or len(observed_ips) < 2:
        return ProxyQueryResult(proxy=proxy, result=ProxyInfo(name=name), success=False)
    counts = {code: votes.count(code) for code in set(votes)}
    country = max(counts, key=counts.get)
    if counts[country] < 2 or len(set(observed_ips)) != 1:
        return ProxyQueryResult(proxy=proxy, result=ProxyInfo(name=name), success=False)
    if ip_seen:
        proxy["_egress_ip"] = ip_seen
    proxy["_geo_method"] = "two-or-more-api-country-and-ip-consensus"
    return ProxyQueryResult(
        proxy=proxy,
        result=ProxyInfo(name=name, country=country),
        success=True,
    )


def locate_us(nodes, reader=None):
    us_nodes, country_confirmed = [], 0
    confirmed_by_type, us_by_type = {}, {}
    for index, batch in enumerate(chunks(nodes, BATCH_SIZE), 1):
        print(f"[geoip-egress] batch {index}, nodes={len(batch)}", flush=True)
        results = location.batch_query(
            proxies=batch,
            func=partial(_geo_api_probe, reader=reader),
            num_threads=16,
            show_progress=False,
            description="Checking actual proxy egress country via independent APIs",
            digits=3,
        )
        for item in results or []:
            if not item or not item.success or not item.result:
                continue
            country = (item.result.country or "").strip().upper()
            if country:
                country_confirmed += 1
                kind = str(item.proxy.get("type", "unknown")).lower()
                confirmed_by_type[kind] = confirmed_by_type.get(kind, 0) + 1
            if country in ("美国", "US"):
                proxy = item.proxy
                kind = str(proxy.get("type", "unknown")).lower()
                us_by_type[kind] = us_by_type.get(kind, 0) + 1
                proxy["name"] = proxy.pop("_original_name", proxy.get("name", "US node"))
                us_nodes.append(proxy)
    print(f"[geoip-egress] country confirmed={country_confirmed}; US={len(us_nodes)}", flush=True)
    return us_nodes, country_confirmed, {
        "country_confirmed_by_type": dict(sorted(confirmed_by_type.items())),
        "us_confirmed_by_type": dict(sorted(us_by_type.items())),
    }


def speed_probe(proxy, port):
    latency_samples = []
    speed_samples = []
    headers = location._origin_headers(TEST_URL)
    for _ in range(3):
        started = time.perf_counter()
        try:
            status, _ = location._request_through_proxy(port, TEST_URL, headers, timeout=15)
            elapsed = (time.perf_counter() - started) * 1000
            if status in (200, 204):
                latency_samples.append(elapsed)
        except Exception:
            pass

    download_url = SPEED_URL.format(SPEED_BYTES)
    download_headers = location._origin_headers(download_url)
    for _ in range(2):
        started = time.perf_counter()
        try:
            status, body = location._request_through_proxy(
                port, download_url, download_headers, timeout=25
            )
            elapsed = max(time.perf_counter() - started, 0.001)
            if status == 200 and len(body) >= int(SPEED_BYTES * 0.75):
                speed_samples.append(len(body) * 8 / elapsed / 1_000_000)
        except Exception:
            pass

    proxy["_latency_samples"] = latency_samples
    proxy["_speed_samples"] = speed_samples
    proxy["_latency_ms"] = statistics.median(latency_samples) if latency_samples else 99999.0
    proxy["_speed_mbps"] = statistics.median(speed_samples) if speed_samples else 0.0
    if latency_samples:
        mean_latency = statistics.mean(latency_samples)
        jitter = statistics.pstdev(latency_samples) / max(mean_latency, 1.0)
    else:
        jitter = 1.0
    proxy["_stability"] = (len(latency_samples) / 3.0) / (1.0 + jitter)
    ok = len(latency_samples) >= 3 and len(speed_samples) >= 2
    return ProxyQueryResult(
        proxy=proxy,
        result=ProxyInfo(name=str(proxy.get("name", ""))),
        success=ok,
    )


def measure_and_rank(nodes):
    measured = []
    for index, batch in enumerate(chunks(nodes, BATCH_SIZE), 1):
        print(f"[speed] batch {index}, US nodes={len(batch)}", flush=True)
        results = location.batch_query(
            proxies=batch,
            func=speed_probe,
            num_threads=16,
            show_progress=False,
            description="Measuring latency and throughput",
            digits=3,
        )
        for item in results or []:
            if not item or not item.success:
                continue
            proxy = item.proxy
            latency = float(proxy.get("_latency_ms", 99999.0))
            speed = float(proxy.get("_speed_mbps", 0.0))
            stability = float(proxy.get("_stability", 0.0))
            latency_score = 1.0 / (1.0 + latency / 100.0)
            speed_score = speed / (speed + 10.0)
            score = 0.45 * latency_score + 0.40 * speed_score + 0.15 * stability
            proxy["_score"] = score
            measured.append(proxy)
    measured.sort(
        key=lambda p: (
            -float(p.get("_score", 0)),
            float(p.get("_latency_ms", 99999)),
            -float(p.get("_speed_mbps", 0)),
        )
    )
    return measured


def validate_exported_candidates(nodes, clash_bin):
    """Re-test cleaned, export-shaped proxies through Mihomo before publishing.

    This catches parser/serializer and outbound-field issues that can be hidden
    when testing the raw crawler objects. A failed batch is split recursively
    so one malformed node cannot invalidate otherwise usable candidates.
    """
    valid = []
    tested_by_type, passed_by_type, rejected_by_type = {}, {}, {}
    test_counter = 0

    def test_batch(batch):
        nonlocal test_counter
        if not batch:
            return
        test_counter += 1
        label = f"export-check-{test_counter:03d}"
        test_proxies = []
        original_by_name = {}
        for original in batch:
            test_proxy, _ = clean_proxy(original, len(test_proxies) + 1)
            test_proxy["name"] = f"EXPORT-{test_counter:03d}-{len(test_proxies) + 1:03d}"
            test_proxies.append(test_proxy)
            original_by_name[test_proxy["name"]] = original

        names = [item["name"] for item in test_proxies]
        test_config = {
            "mixed-port": 7890,
            "external-controller": clash.EXTERNAL_CONTROLLER,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "proxies": test_proxies,
            "proxy-groups": [
                {"name": "EXPORT-CHECK", "type": "select", "proxies": names},
            ],
            "rules": ["MATCH,EXPORT-CHECK"],
        }
        config_path = WORKSPACE / f"{label}.yaml"
        with config_path.open("w", encoding="utf-8") as handle:
            yaml.dump(
                test_config, handle, Dumper=PlainSafeDumper,
                allow_unicode=True, sort_keys=False,
            )

        binpath = WORKSPACE / clash_bin
        syntax = subprocess.run(
            [str(binpath), "-t", "-d", str(WORKSPACE), "-f", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=35,
        )
        if syntax.returncode != 0:
            if len(batch) > 1:
                middle = len(batch) // 2
                test_batch(batch[:middle])
                test_batch(batch[middle:])
            else:
                item = batch[0]
                kind = str(item.get("type", "unknown")).lower()
                tested_by_type[kind] = tested_by_type.get(kind, 0) + 1
                rejected_by_type[kind] = rejected_by_type.get(kind, 0) + 1
                print(
                    f"[export-check] rejected invalid exported config: "
                    f"type={kind}, name={item.get('name', '')}, "
                    f"detail={syntax.stdout[-500:]}",
                    flush=True,
                )
            return

        process = subprocess.Popen(
            [str(binpath), "-d", str(WORKSPACE), "-f", str(config_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(6)
            params = [
                [item, clash.EXTERNAL_CONTROLLER, 15000, TEST_URL, 15000, False]
                for item in test_proxies
            ]
            masks = utils.multi_thread_run(
                func=clash.check,
                tasks=params,
                num_threads=min(16, max(1, len(params))),
                show_progress=False,
                description="Re-testing cleaned exported proxies",
            ) or []
            for index, original in enumerate(batch):
                kind = str(original.get("type", "unknown")).lower()
                tested_by_type[kind] = tested_by_type.get(kind, 0) + 1
                passed = index < len(masks) and bool(masks[index])
                if passed:
                    valid.append(original)
                    passed_by_type[kind] = passed_by_type.get(kind, 0) + 1
                else:
                    rejected_by_type[kind] = rejected_by_type.get(kind, 0) + 1
        finally:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
            try:
                config_path.unlink(missing_ok=True)
            except Exception:
                pass

    for batch in chunks(nodes, 10):
        test_batch(batch)

    # Preserve the original global score order after the batch-wise checks.
    valid_ids = {id(item) for item in valid}
    valid = [item for item in nodes if id(item) in valid_ids]
    return valid, {
        "tested_by_protocol": dict(sorted(tested_by_type.items())),
        "passed_by_protocol": dict(sorted(passed_by_type.items())),
        "rejected_by_protocol": dict(sorted(rejected_by_type.items())),
    }


def _yaml_plain(value):
    """Convert library-specific values to standard YAML-safe Python types."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _yaml_plain(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_yaml_plain(val) for val in value]
    # Enums and custom scalar wrappers sometimes leak from parsed proxy objects.
    enum_value = getattr(value, "value", None)
    if enum_value is not None and enum_value is not value:
        return _yaml_plain(enum_value)
    return str(value)


class PlainSafeDumper(yaml.SafeDumper):
    """Safely serialize parser/library scalar wrappers as plain YAML scalars."""
    def represent_data(self, data):
        if type(data) not in (str, int, float, bool, type(None), dict, list, tuple):
            if isinstance(data, Mapping):
                data = {str(key): value for key, value in data.items()}
            elif isinstance(data, (list, tuple, set)):
                data = list(data)
            else:
                data = str(data)
        return super().represent_data(data)


def clean_proxy(proxy, rank):
    item = _yaml_plain(dict(proxy))
    original = item.pop("_original_name", item.get("name", "node"))
    item.pop("_latency_samples", None)
    item.pop("_speed_samples", None)
    latency = float(item.pop("_latency_ms", 0))
    speed = float(item.pop("_speed_mbps", 0))
    stability = float(item.pop("_stability", 0))
    score = float(item.pop("_score", 0))
    item.pop("sub", None)
    item.pop("_egress_ip", None)
    item.pop("_geo_method", None)
    item.pop("liveness", None)
    item.pop("cdn", None)
    item.pop("renamed", None)
    item["name"] = f"US-{rank:03d} | {str(original)[:48]}"
    return item, {
        "rank": rank,
        "name": item["name"],
        "type": item.get("type", ""),
        "latency_ms": round(latency, 1),
        "download_mbps": round(speed, 2),
        "stability_score": round(stability, 3),
        "score": round(score, 5),
    }



def collect_public_feeds(groups):
    """Collect two openly published feeds; each candidate is independently re-tested."""
    push_to = list(groups.keys())
    stats = {"pawdroid_uris": 0, "au1rxx_proxies": 0}
    if not push_to:
        print("[public-feeds] skipped: no output group configured", flush=True)
        return [], stats

    sites = []
    # Pawdroid's README documents this as a public, refreshed subscription feed.
    try:
        raw = utils.http_get(
            url="https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
            retry=2, timeout=45,
        )
        if raw:
            compact = re.sub(r"\s+", "", raw.strip())
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="ignore")
            uris = list(dict.fromkeys(
                re.findall(r"(?im)^(?:vmess|vless|trojan|ss|ssr|snell|hysteria|hysteria2|tuic|anytls|socks5|https?)://[^\s]+", decoded)
            ))
            if uris:
                sites.append(SiteConfig(
                    name="public-pawdroid",
                    nodes=NodeInput(uris=uris),
                    push_to=push_to,
                    origin="PUBLIC_FEED",
                ))
                stats["pawdroid_uris"] = len(uris)
    except Exception as exc:
        print(f"[public-feeds] Pawdroid fetch/parse failed: {exc}", flush=True)

    # The user previously confirmed HTTP and Hysteria nodes from this feed
    # work in Clash Mi. Import all supported protocols, but still re-test every
    # candidate and independently verify its actual US egress.
    try:
        raw = utils.http_get(
            url="https://www.ermao.net/sub/clash/ermao.net",
            retry=2, timeout=60,
        )
        ermao_proxies, ermao_uris = [], []
        if raw:
            try:
                parsed_feed = yaml.safe_load(raw)
            except Exception:
                parsed_feed = None
            if isinstance(parsed_feed, dict):
                ermao_proxies = [
                    item for item in parsed_feed.get("proxies", [])
                    if isinstance(item, dict)
                    and str(item.get("type", "")).lower() in ALLOWED_TYPES
                    and item.get("server") and item.get("port")
                ]
            if not ermao_proxies:
                candidate_text = raw.strip()
                try:
                    decoded = base64.b64decode(
                        re.sub(r"\s+", "", candidate_text) + "=" * (-len(re.sub(r"\s+", "", candidate_text)) % 4)
                    ).decode("utf-8", errors="ignore")
                    if decoded:
                        candidate_text = decoded
                except Exception:
                    pass
                ermao_uris = list(dict.fromkeys(re.findall(
                    r"(?im)^(?:vmess|vless|trojan|ss|ssr|snell|hysteria|hysteria2|tuic|anytls|socks5|https?)://[^\s]+",
                    candidate_text,
                )))
        if ermao_proxies or ermao_uris:
            sites.append(SiteConfig(
                name="public-ermao-clash-mi-tested",
                nodes=NodeInput(proxies=ermao_proxies, uris=ermao_uris),
                push_to=push_to,
                origin="PUBLIC_FEED",
            ))
        stats["ermao_proxies"] = len(ermao_proxies)
        stats["ermao_uris"] = len(ermao_uris)
    except Exception as exc:
        print(f"[public-feeds] ermao fetch/parse failed: {exc}", flush=True)

    # This feed is pre-labelled US, but that label is deliberately NOT trusted:
    # all imported nodes must pass our own live-proxy egress GeoIP test.
    try:
        raw = utils.http_get(
            url="https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-US.yaml",
            retry=2, timeout=45,
        )
        data = yaml.safe_load(raw) if raw else {}
        proxies = data.get("proxies", []) if isinstance(data, dict) else []
        proxies = [
            item for item in proxies
            if isinstance(item, dict)
            and str(item.get("type", "")).lower() in ALLOWED_TYPES
            and item.get("server") and item.get("port")
        ]
        if proxies:
            sites.append(SiteConfig(
                name="public-au1rxx-us-shard",
                nodes=NodeInput(proxies=proxies),
                push_to=push_to,
                origin="PUBLIC_FEED",
            ))
            stats["au1rxx_proxies"] = len(proxies)
    except Exception as exc:
        print(f"[public-feeds] Au1rxx fetch/parse failed: {exc}", flush=True)

    # Additional independently maintained public feeds. Country labels are never trusted.
    # Every candidate still passes Mihomo, actual egress-country and speed checks.
    extra_feeds = [
        ("mfuu_freeproxies", "https://raw.githubusercontent.com/mfuu/FreeProxies/master/sub.yaml"),
        ("share_daily_nodes", "https://raw.githubusercontent.com/share-daily/node/main/clash.yaml"),
        ("free_nodes_735754647", "https://735754647.github.io/Free-Nodes/clash.yaml"),
        ("nodesradar", "https://radarhub.top/clash.yaml"),
    ]
    for feed_name, feed_url in extra_feeds:
        try:
            raw = utils.http_get(url=feed_url, retry=2, timeout=60)
            data = yaml.safe_load(raw) if raw else {}
            proxies = data.get("proxies", []) if isinstance(data, dict) else []
            proxies = [
                item for item in proxies
                if isinstance(item, dict)
                and str(item.get("type", "")).lower() in ALLOWED_TYPES
                and item.get("server") and item.get("port")
            ]
            stats[feed_name] = len(proxies)
            if proxies:
                sites.append(SiteConfig(
                    name=f"public-{feed_name}",
                    nodes=NodeInput(proxies=proxies),
                    push_to=push_to,
                    origin="PUBLIC_FEED",
                ))
            print(f"[public-feeds] {feed_name}: imported {len(proxies)} YAML proxies", flush=True)
        except Exception as exc:
            stats[feed_name] = 0
            print(f"[public-feeds] {feed_name} fetch/parse failed: {exc}", flush=True)

    print(f"[public-feeds] imported={stats}", flush=True)
    return sites, stats

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Never let a failed/short run accidentally archive or publish yesterday's file.
    (OUT / "us_top36.yaml").unlink(missing_ok=True)
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "runner": "GitHub Actions ubuntu-latest",
        "sources": ["Telegram", "Yandex Search", "GitHub Code/Issues", "Pawdroid/Free-servers", "Au1rxx/free-vpn-subscriptions (US shard, re-verified)", "mfuu/FreeProxies", "share-daily/node", "735754647/Free-Nodes", "nodesradar/nodesradar-en"],
        "raw_candidates": 0,
        "parsed_supported": 0,
        "alive": 0,
        "egress_country_confirmed": 0,
        "us_egress_confirmed": 0,
        "speed_measured": 0,
        "final_count": 0,
        "target_count": 36,
        "protocol_counts": {},
        "stage_counts": {},
        "notes": [
            "Country is checked through each proxy's actual egress connection, not the node label or origin server IP.",
            "Cloud runner measurements are not the user's phone-network measurements.",
            "Download speed uses two 512 KiB Cloudflare test downloads per confirmed US node.",
        ],
    }
    try:
        config_url = os.environ.get("SUBSCRIBE_CONF", "").strip()
        if not config_url:
            raise RuntimeError("Missing repository secret SUBSCRIBE_CONF")
        raw_config = utils.http_get(url=config_url, retry=3, timeout=120)
        if not raw_config:
            raise RuntimeError("Could not download the existing Aggregator configuration")
        pc = ProcessConfig.parse(json.loads(raw_config))
        if not pc.crawl:
            raise RuntimeError("Crawler configuration is missing in SUBSCRIBE_CONF")

        # Use three complementary public sources: configured Telegram channels,
        # Yandex subscription search, and GitHub code/issues search.
        for key in ("google", "twitter"):
            section = getattr(pc.crawl, key, None)
            if section is not None:
                section.enable = False
        pc.crawl.repositories = []
        pc.crawl.pages = []
        pc.crawl.scripts = []
        if pc.crawl.telegram is not None:
            pc.crawl.telegram.enable = True
            pc.crawl.telegram.pages = 5
        if pc.crawl.yandex is None:
            pc.crawl.yandex = YandexConfig()
        pc.crawl.yandex.enable = True
        pc.crawl.yandex.pages = 5
        if pc.crawl.github is None:
            pc.crawl.github = GithubConfig()
        pc.crawl.github.enable = True
        pc.crawl.github.pages = 5

        # Exclude unrelated preconfigured sites from this source-focused run.
        pc.sites = []

        pushtool = push.get_instance(pc.storage)
        pc.verify(pushtool)
        collected_sites = crawl_engine.run(
            config=pc.crawl,
            storage=pc.storage,
            num_threads=32,
            display=False,
            mode=0,
        ) or []
        public_sites, public_stats = collect_public_feeds(pc.groups)
        collected_sites.extend(public_sites)
        report["public_feed_stats"] = public_stats
        report["collected_sites"] = len(collected_sites)
        report["collected_site_names"] = [str(getattr(site, "name", "")) for site in collected_sites]
        report["sites_by_source"] = {}
        for site in collected_sites or []:
            source = str(getattr(site, "origin", "unknown"))
            report["sites_by_source"][source] = report["sites_by_source"].get(source, 0) + 1
        if not collected_sites:
            raise RuntimeError("All configured crawlers and independent public feeds returned no usable sources")

        clash_bin, subconverter_bin = executable.which_bin()
        utils.chmod(str(WORKSPACE / clash_bin))
        utils.chmod(str(ROOT / "subconverter" / subconverter_bin))

        tasks, _ = pipeline.assign_sites(
            sites=collected_sites,
            groups=pc.groups,
            retry=2,
            bin_name=subconverter_bin,
            allow_gmail_alias=False,
            special_protocols=True,
        )
        report["created_tasks"] = len(tasks)
        report["task_names"] = [task.name for task in tasks]
        report["task_input_counts"] = [
            {"name": task.name, "subscriptions": len(task.nodes.subscribe_list()),
             "uris": len(task.nodes.uris), "proxies": len(task.nodes.proxies)}
            for task in tasks
        ]
        if not tasks:
            raise RuntimeError("No valid subscription tasks were created from the collected public sources")
        task_results = utils.multi_process_run(
            func=workflow.executewrapper,
            tasks=tasks,
        ) or []
        parsed_all = []
        report["task_parse_counts"] = []
        for result in task_results:
            task_id = result[0] if result else -1
            task_nodes = result[1] if result and len(result) >= 2 and result[1] else []
            report["task_parse_counts"].append({
                "task_id": task_id,
                "parsed": len(task_nodes),
                "protocols": protocol_counts(task_nodes),
            })
            parsed_all.extend(task_nodes)
        report["parsed_all_by_type"] = protocol_counts(parsed_all)
        rejected = {"not_dict": 0, "unsupported_type": 0, "missing_server": 0, "missing_port": 0}
        parsed = []
        for p in parsed_all:
            if not isinstance(p, dict):
                rejected["not_dict"] += 1
                continue
            kind = str(p.get("type", "")).lower()
            if kind not in ALLOWED_TYPES:
                rejected["unsupported_type"] += 1
                continue
            if not p.get("server"):
                rejected["missing_server"] += 1
                continue
            if not p.get("port"):
                rejected["missing_port"] += 1
                continue
            parsed.append(p)
        report["parse_rejections"] = rejected
        report["parsed_supported_by_type"] = protocol_counts(parsed)
        unique = {}
        for p in parsed:
            key = (
                str(p.get("type", "")).lower(),
                str(p.get("server", "")).lower(),
                str(p.get("port", "")),
                str(p.get("uuid", p.get("password", ""))),
                str(p.get("sni", p.get("servername", ""))).lower(),
            )
            unique.setdefault(key, p)
        candidates = list(unique.values())
        report["raw_candidates"] = len(parsed)
        report["parsed_supported"] = len(candidates)
        report["protocol_counts"]["parsed_unique"] = protocol_counts(candidates)
        report["stage_counts"]["parsed_unique"] = len(candidates)
        if len(candidates) > MAX_CANDIDATES:
            random.Random(20261113).shuffle(candidates)
            candidates = candidates[:MAX_CANDIDATES]
        print(f"[parse] supported unique candidates={len(candidates)}", flush=True)
        if not candidates:
            raise RuntimeError("No supported VMess/VLESS/Trojan/SS nodes parsed")

        alive = run_alive_check(candidates, clash_bin)
        report["alive"] = len(alive)
        report["protocol_counts"]["alive"] = protocol_counts(alive)
        report["stage_counts"]["alive"] = len(alive)
        print(f"[alive] passed={len(alive)}", flush=True)
        if not alive:
            raise RuntimeError("No node passed Mihomo connectivity tests")

        for p in alive:
            p["_original_name"] = str(p.get("name", "node"))

        mmdb_dir = OUT / "geoip"
        mmdb_dir.mkdir(exist_ok=True)
        # MMDB download is best-effort only. Actual egress country is verified
        # through independent HTTPS APIs via each proxy, so a broken GitHub
        # release/API cannot invalidate the whole run.
        reader = None
        try:
            reader = location.load_mmdb(
                directory=str(mmdb_dir),
                repo="Loyalsoldier/geoip",
                filename="Country.mmdb",
                update=True,
            )
        except Exception as exc:
            print(f"[geoip] optional MMDB unavailable; using online APIs: {exc}", flush=True)
        try:
            us_nodes, confirmed, geo_protocol_stats = locate_us(alive, reader)
        finally:
            if reader:
                reader.close()
        report["egress_country_confirmed"] = confirmed
        report["us_egress_confirmed"] = len(us_nodes)
        report["geo_protocol_counts"] = geo_protocol_stats
        report["protocol_counts"]["us_egress_confirmed"] = protocol_counts(us_nodes)
        report["stage_counts"]["country_confirmed"] = confirmed
        report["stage_counts"]["us_egress_confirmed"] = len(us_nodes)
        report["geoip_method"] = "at least two independent online APIs must agree on country and exact egress IP"
        print(f"[geoip-egress] US confirmed={len(us_nodes)}", flush=True)
        if not us_nodes:
            raise RuntimeError("No live node had a verifiably US egress IP")

        measured = measure_and_rank(us_nodes)
        report["speed_measured"] = len(measured)
        report["protocol_counts"]["speed_measured"] = protocol_counts(measured)
        report["stage_counts"]["speed_measured"] = len(measured)
        diverse, seen_endpoints, seen_egress_ips = [], set(), set()
        for proxy in measured:
            endpoint = (str(proxy.get("server", "")).lower(), str(proxy.get("port", "")))
            egress_ip = str(proxy.get("_egress_ip", "")).strip()
            if not endpoint[0] or not endpoint[1] or endpoint in seen_endpoints:
                continue
            if egress_ip and egress_ip in seen_egress_ips:
                continue
            seen_endpoints.add(endpoint)
            if egress_ip:
                seen_egress_ips.add(egress_ip)
            diverse.append(proxy)
        report["unique_server_endpoints_after_dedup"] = len(seen_endpoints)
        report["unique_us_egress_ips_after_dedup"] = len(seen_egress_ips)
        report["protocol_counts"]["after_dedup"] = protocol_counts(diverse)
        report["stage_counts"]["after_dedup"] = len(diverse)

        # Critical extra gate: re-test the exact cleaned proxy fields that will
        # be written to the subscription, using Mihomo's config validator and
        # three live HTTPS delay targets through each exported proxy.
        export_valid, export_validation = validate_exported_candidates(diverse, clash_bin)
        report["exported_config_validation"] = export_validation
        report["protocol_counts"]["export_config_validated"] = protocol_counts(export_valid)
        report["stage_counts"]["export_config_validated"] = len(export_valid)
        print(
            f"[export-check] passed={len(export_valid)}/{len(diverse)}; "
            f"protocols={protocol_counts(export_valid)}",
            flush=True,
        )
        diverse = export_valid

        top, selection_quota = select_protocol_diverse(
            diverse, target=36, minimum_per_protocol=3
        )
        report["protocol_selection_minimum"] = 3
        report["protocol_selection_quota"] = selection_quota
        report["protocols_available_after_export_validation"] = protocol_counts(diverse)
        if not top:
            raise RuntimeError("No US node passed the exported-config compatibility checks")

        clean_nodes, ranking = [], []
        for rank, proxy in enumerate(top, 1):
            node, row = clean_proxy(proxy, rank)
            clean_nodes.append(node)
            ranking.append(row)

        names = [p["name"] for p in clean_nodes]
        config = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "proxies": clean_nodes,
            "proxy-groups": [
                {"name": "美国优选36", "type": "select", "proxies": names},
                {
                    "name": "美国自动测速36",
                    "type": "url-test",
                    "proxies": names,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 300,
                    "tolerance": 100,
                },
            ],
            "rules": ["MATCH,美国优选50"],
        }
        subscription_path = OUT / "us_top36.yaml"
        with subscription_path.open("w", encoding="utf-8") as handle:
            yaml.dump(config, handle, Dumper=PlainSafeDumper, allow_unicode=True, sort_keys=False)

        # Validate the complete final YAML (including proxy-groups/rules) before
        # the workflow is allowed to publish it. The controller exists only in
        # this temporary validation copy and is never included in the user file.
        final_validation = dict(config)
        final_validation["external-controller"] = clash.EXTERNAL_CONTROLLER
        final_check_path = WORKSPACE / "us_top50_final_validation.yaml"
        with final_check_path.open("w", encoding="utf-8") as handle:
            yaml.dump(
                final_validation, handle, Dumper=PlainSafeDumper,
                allow_unicode=True, sort_keys=False,
            )
        final_syntax = subprocess.run(
            [str(WORKSPACE / clash_bin), "-t", "-d", str(WORKSPACE), "-f", str(final_check_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=35,
        )
        report["final_yaml_syntax_check"] = {
            "passed": final_syntax.returncode == 0,
            "detail": final_syntax.stdout[-1500:],
        }
        final_check_path.unlink(missing_ok=True)
        if final_syntax.returncode != 0:
            raise RuntimeError(
                "The complete final subscription YAML failed Mihomo config validation: "
                + final_syntax.stdout[-1000:]
            )

        report["final_count"] = len(clean_nodes)
        report["protocol_counts"]["final"] = protocol_counts(clean_nodes)
        report["stage_counts"]["final"] = len(clean_nodes)
        report["ranking"] = ranking
        if len(clean_nodes) < report["target_count"]:
            report["status"] = "insufficient"
            report["error"] = (
                f"Only {len(clean_nodes)} verified unique US nodes; "
                f"{report['target_count']} required. Previous subscription will not be published."
            )
        else:
            report["status"] = "success"
        report["test_limits"] = (
            "Latency is the median of up to three HTTPS 204 requests. Download speed is the median of "
            "up to two 512 KiB Cloudflare downloads. These are GitHub runner results, not handset results."
        )
    except Exception as exc:
        report["status"] = "incomplete"
        report["error"] = str(exc)
        print(f"[ERROR] {exc}", flush=True)
    finally:
        (OUT / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    if report.get("status") != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
