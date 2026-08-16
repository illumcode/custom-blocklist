#!/usr/bin/env python3
"""
update_lists.py — генератор/обновлятор твоих .lst-файлов для splify2.

Идея взята из generator/ проекта ru-bypass-ipsets: каждый список описывается
не руками, а РЕЦЕПТОМ (домены → резолв, ASN → CIDR через API, готовый CDN-фид).
Скрипт запускает рецепты, схлопывает результат и сравнивает с тем, что уже
лежит на диске — чтобы было видно, что реально поменялось.

Запуск:
    pip install dnspython requests
    python3 update_lists.py                 # обновить всё
    python3 update_lists.py --only telegram,youtube
    python3 update_lists.py --dry-run        # только показать диф, не писать файлы
    python3 update_lists.py --list           # показать список сервисов и рецептов

Файлы читаются/пишутся в той же папке, что и сам скрипт (или --dir).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

import dns.resolver
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("update_lists")

HTTP_TIMEOUT = (10, 30)
UA = "personal-bypass-lists/1.0"

# ─────────────────────────── DNS-резолв доменов ───────────────────────────

# Несколько независимых публичных резолверов — опрашиваем их параллельно и
# берём объединение ответов. Так учитываются гео-балансировка и то, что
# разные резолверы иногда отдают разные IP одного домена.
NAMESERVERS = [
    "1.1.1.1",         # Cloudflare
    "8.8.8.8",         # Google
    "9.9.9.9",         # Quad9
    "208.67.222.222",  # OpenDNS
]

# Резолверы никогда не должны попадать в списки обхода — иначе после
# включения списка DNS сам уходит в туннель и всё резолвится через раз.
RESOLVER_NETS = [ipaddress.ip_network(n) for n in (
    "1.1.1.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "208.67.222.0/24",
)]


def _query_ns(ns: str, domain: str) -> set[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ns]
    resolver.timeout = 3.0
    resolver.lifetime = 5.0
    out: set[str] = set()
    try:
        for rdata in resolver.resolve(domain, "A"):
            try:
                ip = ipaddress.ip_address(str(rdata.address))
                if ip.is_global:
                    out.add(str(ip))
            except ValueError:
                pass
    except Exception:
        pass
    return out


def resolve_domain(domain: str) -> set[str]:
    ips: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(NAMESERVERS)) as pool:
        futs = [pool.submit(_query_ns, ns, domain) for ns in NAMESERVERS]
        for f in concurrent.futures.as_completed(futs):
            ips |= f.result()
    return ips


def resolve_domains(domains: list[str]) -> list[ipaddress.IPv4Network]:
    """Резолвит список доменов в /24-подсети (соседние IP того же сервиса).
    Адреса самих DNS-резолверов (1.1.1.1, 8.8.8.8 и т.д.) отфильтровываются
    здесь, а не глобально — потому что для CDN-фидов (например Cloudflare)
    1.1.1.0/24 может быть легитимным собственным диапазоном провайдера, а не
    просто адресом резолвера."""
    nets: list[ipaddress.IPv4Network] = []
    dead: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futs = {pool.submit(resolve_domain, d): d for d in domains}
        for fut in concurrent.futures.as_completed(futs):
            d = futs[fut]
            ips = fut.result()
            if not ips:
                dead.append(d)
                continue
            for ip in ips:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                if any(net.overlaps(r) for r in RESOLVER_NETS):
                    continue
                nets.append(net)
    if dead:
        log.info("  не резолвятся (проверь, живы ли ещё): %s", ", ".join(sorted(dead)))
    return nets


# ─────────────────────────── ASN → CIDR (с фолбэком) ───────────────────────

def _from_ripestat(asn: int) -> list[str]:
    try:
        r = requests.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}",
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        return [p["prefix"] for p in data.get("data", {}).get("prefixes", [])
                if ":" not in p["prefix"]]
    except Exception as exc:
        log.debug("RIPEstat AS%s: %s", asn, exc)
        return []


def _from_ipguide(asn: int) -> list[str]:
    try:
        r = requests.get(f"https://ip.guide/as{asn}", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        out = []
        for entry in data.get("prefixes", []):
            net = entry.get("net") or entry.get("prefix") or entry
            if isinstance(net, str) and ":" not in net:
                out.append(net)
        return out
    except Exception as exc:
        log.debug("ip.guide AS%s: %s", asn, exc)
        return []


def _from_bgpview(asn: int) -> list[str]:
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        return [p["prefix"] for p in data.get("data", {}).get("ipv4_prefixes", [])]
    except Exception as exc:
        log.debug("bgpview AS%s: %s", asn, exc)
        return []


def asn_to_networks(asn: int) -> list[ipaddress.IPv4Network]:
    """Все анонсируемые IPv4-префиксы ASN. Пробует три источника по очереди —
    если один недоступен/пустой, берём следующий."""
    for getter in (_from_ripestat, _from_ipguide, _from_bgpview):
        prefixes = getter(asn)
        if prefixes:
            nets = []
            for p in prefixes:
                try:
                    nets.append(ipaddress.ip_network(p, strict=False))
                except ValueError:
                    pass
            if nets:
                log.info("  AS%s: %d префиксов (%s)", asn, len(nets), getter.__name__)
                return nets
    log.warning("  AS%s: ни один источник не ответил", asn)
    return []


# ─────────────────────────── готовые CDN-фиды ───────────────────────────

def fetch_cloudflare() -> list[ipaddress.IPv4Network]:
    r = requests.get("https://www.cloudflare.com/ips-v4", timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    return [ipaddress.ip_network(l.strip(), strict=False) for l in r.text.splitlines() if l.strip()]


def fetch_cloudfront() -> list[ipaddress.IPv4Network]:
    r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    data = r.json()
    return [ipaddress.ip_network(e["ip_prefix"], strict=False)
            for e in data.get("prefixes", []) if e.get("service") == "CLOUDFRONT"]


def fetch_google_ranges() -> list[ipaddress.IPv4Network]:
    """Официальный полный список сетей Google: https://www.gstatic.com/ipranges/goog.json
    Нужен для YouTube — видео раздаётся с огромного числа edge-узлов по всему
    миру, и один снимок DNS-резолва доменов физически не может поймать их все."""
    r = requests.get("https://www.gstatic.com/ipranges/goog.json", timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    data = r.json()
    nets = []
    for entry in data.get("prefixes", []):
        p = entry.get("ipv4Prefix")
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            nets.append(net)
    return nets


def fetch_github_meta() -> list[ipaddress.IPv4Network]:
    """Официальный список IP GitHub: https://api.github.com/meta
    Берём все категории (web, api, git, packages, pages, actions, importer, hooks, ...) —
    GitHub добавляет новые ключи со временем, поэтому не завязываемся на конкретный список."""
    r = requests.get("https://api.github.com/meta", timeout=HTTP_TIMEOUT,
                      headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    r.raise_for_status()
    data = r.json()
    nets = []
    for key, value in data.items():
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, str):
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network):
                nets.append(net)
    return nets


def fetch_telegram_official() -> list[ipaddress.IPv4Network]:
    r = requests.get("https://core.telegram.org/resources/cidr.txt", timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    nets = []
    for l in r.text.splitlines():
        l = l.strip()
        if not l:
            continue
        try:
            net = ipaddress.ip_network(l, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):  # файл содержит и IPv6 — нам нужен только v4
            nets.append(net)
    return nets


# ─────────────────────────── общая нормализация ───────────────────────────

def finalize(nets: list[ipaddress.IPv4Network]) -> list[str]:
    """Дедуп + схлопывание смежных сетей + сортировка."""
    nets = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]  # на случай, если источник подсунет IPv6
    uniq = list({n for n in nets})
    collapsed = list(ipaddress.collapse_addresses(uniq)) if uniq else []
    collapsed.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in collapsed]


def read_lst(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]


def write_lst(path: Path, lines: list[str]) -> None:
    path.write_text("\r\n".join(lines) + ("\r\n" if lines else ""), encoding="utf-8")


def diff_report(name: str, old: list[str], new: list[str]) -> None:
    old_s, new_s = set(old), set(new)
    added = sorted(new_s - old_s)
    removed = sorted(old_s - new_s)
    if not added and not removed:
        log.info("  %s: без изменений (%d записей)", name, len(new))
        return
    log.info("  %s: было %d -> стало %d  (+%d / -%d)", name, len(old), len(new), len(added), len(removed))
    for a in added[:5]:
        log.info("    + %s", a)
    if len(added) > 5:
        log.info("    ... и ещё %d добавленных", len(added) - 5)
    for r in removed[:5]:
        log.info("    - %s", r)
    if len(removed) > 5:
        log.info("    ... и ещё %d удалённых", len(removed) - 5)


# ─────────────────────────── конфиг сервисов ───────────────────────────
#
# Каждый сервис — набор "рецептов" (sources), результаты которых объединяются
# в один выходной .lst. domains_file (если указан) читается с диска: это
# ручной список доменов, который ты сам поддерживаешь отдельно.
#
# Чтобы добавить свой сервис — допиши сюда запись, файлы создавать не нужно,
# скрипт сам напишет .lst при первом запуске.

@dataclass
class Source:
    kind: str                # "resolve" | "asn" | "cloudflare" | "cloudfront" | "official_url" | "github_meta" | "google_full" | "extra_cidrs"
    asn: int | None = None
    url: str | None = None
    cidrs: list[str] = field(default_factory=list)


@dataclass
class Service:
    ip_file: str
    domains_file: str | None = None
    sources: list[Source] = field(default_factory=list)


SERVICES: dict[str, Service] = {
    "telegram": Service(
        ip_file="telegram_ip.lst",
        domains_file="telegram_domains.lst",
        sources=[Source("official_url", url="https://core.telegram.org/resources/cidr.txt")],
    ),
    "youtube": Service(
        ip_file="youtube_ip.lst",
        domains_file="youtube_domains.lst",
        sources=[Source("resolve"), Source("google_full")],
    ),
    "gemini": Service(
        ip_file="gemini_ip_fix.lst",
        domains_file="gemini_domains.lst",
        sources=[
            Source("resolve"),
            # Основные блоки Google (AS15169). Нужны отдельно от resolve, потому что
            # некоторые бэкенды (например waa-pa.clients6.google.com — anti-abuse/
            # attestation токен, критичен для гео-проверки Gemini) — анкаст и на
            # каждый запрос могут отвечать с разных из этих блоков. Один снимок DNS
            # никогда не поймает их все, поэтому блоки закреплены явно.
            Source("extra_cidrs", cidrs=[
                "64.233.160.0/19",
                "66.102.0.0/20",
                "66.249.64.0/19",
                "72.14.192.0/18",
                "74.125.0.0/16",
                "108.177.8.0/21",
                "142.250.0.0/15",
                "172.217.0.0/16",
                "172.253.0.0/16",
                "173.194.0.0/16",
                "209.85.128.0/17",
                "216.58.192.0/19",
            ]),
        ],
    ),
    "claude": Service(
        ip_file="claude_ip.lst",
        domains_file="claude_domains.lst",
        sources=[Source("resolve")],
    ),
    "deepl": Service(
        ip_file="deepl_ip_fix.lst",
        domains_file="deepl_domains.lst",
        sources=[Source("resolve")],
    ),
    "discord": Service(
        ip_file="discord_ip.lst",
        domains_file="discord_domains.lst",
        sources=[Source("resolve"), Source("asn", asn=62041)],
    ),
    "soundcloud": Service(
        ip_file="soundcloud_ip.lst",
        domains_file="soundcloud_domains.lst",
        sources=[Source("resolve"), Source("asn", asn=197157)],
    ),
    "steam": Service(
        ip_file="steam_ip.lst",
        sources=[Source("asn", asn=32590)],  # Valve Corporation
    ),
    "github": Service(
        ip_file="github_ip.lst",
        domains_file="github_domains.lst",
        sources=[Source("resolve"), Source("github_meta")],
    ),
    "cloudflare": Service(
        ip_file="cloudflare_ip.lst",
        sources=[
            Source("cloudflare"),
            # Проверенная руками база: с этим набором Gemini/DeepL/Discord
            # реально работали через splify2. Официальный фид Cloudflare
            # (выше) агрегирует адреса в крупные префиксы (/13, /14 и т.д.),
            # и в паре случаев splify2 с такими диапазонами вёл себя иначе,
            # чем с этим более мелким набором — поэтому держим его как
            # обязательную базу поверх официального фида, а не полагаемся
            # только на агрегированный список.
            Source("extra_cidrs", cidrs=[
        "1.0.0.0/24",
        "1.1.1.0/24",
        "5.10.214.0/23",
        "5.226.183.0/24",
        "5.252.81.0/24",
        "8.6.112.0/24",
        "8.20.125.0/24",
        "8.21.9.0/24",
        "8.21.10.0/24",
        "8.21.111.0/24",
        "8.24.87.0/24",
        "8.25.97.0/24",
        "8.27.64.0/24",
        "8.27.66.0/23",
        "8.27.68.0/24",
        "8.29.109.0/24",
        "8.29.228.0/24",
        "8.29.230.0/23",
        "8.31.160.0/23",
        "8.34.70.0/23",
        "8.34.146.0/24",
        "8.35.211.0/24",
        "8.37.43.0/24",
        "8.39.125.0/24",
        "8.39.204.0/24",
        "8.39.214.0/24",
        "8.44.2.0/24",
        "8.44.61.0/24",
        "8.47.13.0/24",
        "8.47.69.0/24",
        "23.131.204.0/24",
        "23.227.37.0/24",
        "23.227.38.0/23",
        "23.227.42.0/23",
        "23.227.48.0/23",
        "23.227.60.0/24",
        "31.185.108.0/24",
        "35.201.124.0/24",
        "37.153.170.0/23",
        "38.96.28.0/23",
        "42.61.47.0/24",
        "43.228.232.0/23",
        "43.230.112.0/23",
        "43.230.114.0/24",
        "45.12.44.0/23",
        "45.45.255.0/24",
        "45.128.76.0/24",
        "45.130.125.0/24",
        "45.146.130.0/24",
        "45.148.100.0/24",
        "45.157.17.0/24",
        "45.192.223.0/24",
        "45.192.224.0/24",
        "45.195.14.0/24",
        "45.195.153.0/24",
        "45.196.29.0/24",
        "45.198.114.0/24",
        "45.198.116.0/24",
        "45.198.139.0/24",
        "45.199.183.0/24",
        "45.199.188.0/24",
        "45.250.152.0/22",
        "46.38.152.0/24",
        "49.238.236.0/22",
        "51.194.144.0/22",
        "51.241.128.0/23",
        "57.250.49.0/24",
        "61.8.33.0/24",
        "61.32.240.0/24",
        "61.245.108.0/24",
        "62.146.255.0/24",
        "64.8.255.0/24",
        "64.40.138.0/24",
        "64.40.140.0/24",
        "64.239.31.0/24",
        "65.110.63.0/24",
        "66.71.220.0/24",
        "66.80.5.0/24",
        "66.84.82.0/24",
        "66.92.62.0/24",
        "66.93.178.0/24",
        "66.203.249.0/24",
        "66.235.200.0/24",
        "66.242.60.0/23",
        "68.182.187.0/24",
        "69.90.210.0/24",
        "74.1.17.0/24",
        "77.73.113.0/24",
        "78.128.122.0/24",
        "80.240.93.0/24",
        "82.21.82.0/24",
        "82.22.16.0/24",
        "82.25.20.0/24",
        "82.26.156.0/24",
        "82.109.153.0/24",
        "82.139.216.0/23",
        "87.86.16.0/24",
        "87.232.75.0/24",
        "88.216.69.0/24",
        "89.46.251.0/24",
        "89.106.90.0/24",
        "89.249.200.0/24",
        "91.206.71.0/24",
        "91.213.221.0/24",
        "91.224.186.0/24",
        "91.234.202.0/24",
        "92.44.1.0/24",
        "94.156.10.0/24",
        "94.177.26.0/24",
        "96.43.100.0/23",
        "98.98.234.0/24",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "103.31.79.0/24",
        "103.50.96.0/23",
        "103.51.12.0/23",
        "103.54.128.0/23",
        "103.81.228.0/24",
        "103.186.74.0/24",
        "103.198.92.0/24",
        "103.215.22.0/24",
        "103.219.64.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "104.28.0.0/16",
        "104.29.5.0/24",
        "104.29.6.0/24",
        "104.29.9.0/24",
        "104.29.18.0/24",
        "104.29.45.0/24",
        "104.29.63.0/24",
        "104.29.73.0/24",
        "104.29.77.0/24",
        "104.29.92.0/23",
        "104.29.111.0/24",
        "104.29.114.0/24",
        "104.29.121.0/24",
        "104.29.124.0/22",
        "104.29.128.0/18",
        "104.30.0.0/19",
        "104.30.32.0/23",
        "104.30.128.0/23",
        "104.30.132.0/22",
        "104.30.136.0/23",
        "104.30.144.0/21",
        "104.30.160.0/19",
        "104.31.0.0/21",
        "104.31.16.0/22",
        "104.31.20.0/24",
        "104.156.176.0/23",
        "104.234.133.0/24",
        "104.243.192.0/24",
        "104.244.236.0/23",
        "104.249.18.0/24",
        "104.249.43.0/24",
        "108.162.192.0/18",
        "109.234.211.0/24",
        "123.108.75.0/24",
        "123.253.173.0/24",
        "123.253.174.0/24",
        "131.0.72.0/22",
        "131.167.255.0/24",
        "137.66.96.0/24",
        "138.226.212.0/23",
        "138.226.234.0/24",
        "138.249.21.0/24",
        "138.249.126.0/24",
        "138.249.148.0/24",
        "140.233.180.0/24",
        "141.101.64.0/18",
        "143.14.142.0/24",
        "143.14.224.0/24",
        "143.14.251.0/24",
        "144.124.208.0/24",
        "144.124.211.0/24",
        "144.124.212.0/24",
        "144.124.214.0/23",
        "144.208.122.0/24",
        "145.63.64.0/24",
        "145.224.255.0/24",
        "146.19.108.0/24",
        "147.189.42.0/23",
        "148.224.60.0/24",
        "148.227.167.0/24",
        "149.112.78.0/24",
        "150.48.128.0/18",
        "151.243.133.0/24",
        "151.245.127.0/24",
        "151.246.216.0/23",
        "152.114.0.0/17",
        "152.114.128.0/18",
        "154.46.20.0/24",
        "154.81.141.0/24",
        "154.84.164.0/24",
        "154.86.118.0/24",
        "154.193.63.0/24",
        "154.193.133.0/24",
        "154.193.184.0/24",
        "154.200.89.0/24",
        "154.223.134.0/23",
        "155.117.208.0/23",
        "156.11.149.0/24",
        "156.70.60.0/24",
        "156.71.149.0/24",
        "156.224.73.0/24",
        "156.238.181.0/24",
        "156.243.83.0/24",
        "156.246.69.0/24",
        "156.246.70.0/24",
        "157.96.22.0/24",
        "158.94.212.0/24",
        "159.242.242.0/24",
        "161.115.162.0/24",
        "161.248.134.0/23",
        "162.44.104.0/22",
        "162.158.0.0/15",
        "162.251.82.0/24",
        "162.251.205.0/24",
        "165.101.60.0/23",
        "166.88.240.0/24",
        "167.1.137.0/24",
        "167.74.92.0/22",
        "167.74.130.0/24",
        "167.74.142.0/23",
        "168.151.31.0/24",
        "168.183.3.0/24",
        "169.40.40.0/23",
        "169.40.133.0/24",
        "170.168.7.0/24",
        "170.176.163.0/24",
        "172.64.0.0/13",
        "173.0.92.0/24",
        "173.245.48.0/20",
        "176.103.113.0/24",
        "178.83.176.0/24",
        "178.93.117.0/24",
        "178.94.249.0/24",
        "181.215.196.0/24",
        "182.23.210.0/24",
        "185.7.240.0/24",
        "185.18.184.0/24",
        "185.29.76.0/24",
        "185.38.25.0/24",
        "185.41.148.0/24",
        "185.60.251.0/24",
        "185.106.205.0/24",
        "185.132.85.0/24",
        "185.132.86.0/24",
        "185.133.172.0/24",
        "185.146.172.0/23",
        "185.148.181.0/24",
        "185.149.135.0/24",
        "185.156.19.0/24",
        "185.158.133.0/24",
        "185.178.196.0/22",
        "185.229.206.0/24",
        "188.42.98.0/24",
        "188.95.12.0/24",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "191.101.212.0/22",
        "192.71.82.0/24",
        "192.86.150.0/24",
        "192.103.56.0/24",
        "193.8.231.0/24",
        "193.8.237.0/24",
        "193.118.171.0/24",
        "193.135.43.0/24",
        "193.135.44.0/24",
        "193.202.90.0/24",
        "193.202.112.0/24",
        "194.34.64.0/22",
        "194.34.70.0/23",
        "194.34.76.0/24",
        "194.34.78.0/23",
        "194.34.80.0/24",
        "194.34.82.0/23",
        "194.34.84.0/22",
        "194.34.88.0/22",
        "194.34.93.0/24",
        "194.41.114.0/24",
        "194.77.235.0/24",
        "194.152.130.0/24",
        "195.66.29.0/24",
        "195.216.190.0/24",
        "195.242.122.0/23",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "198.52.36.0/24",
        "198.148.174.0/24",
        "198.217.251.0/24",
        "198.252.206.0/24",
        "199.7.70.0/24",
        "199.27.128.0/21",
        "199.65.62.0/24",
        "199.68.16.0/22",
        "200.69.28.0/24",
        "202.27.69.0/24",
        "202.49.114.0/24",
        "203.5.33.0/24",
        "203.15.65.0/24",
        "203.117.8.0/24",
        "203.117.53.0/24",
        "203.120.52.0/24",
        "203.168.192.0/20",
        "204.4.235.0/24",
        "204.62.121.0/24",
        "204.62.122.0/24",
        "204.69.207.0/24",
        "204.153.16.0/24",
        "204.195.192.0/18",
        "205.203.78.0/24",
        "206.206.104.0/23",
        "207.57.150.0/23",
        "207.89.22.0/23",
        "207.207.209.0/24",
        "207.241.180.0/24",
        "208.88.71.0/24",
        "208.184.1.0/24",
        "208.185.162.0/24",
        "209.55.226.0/24",
        "209.55.232.0/24",
        "209.55.234.0/24",
        "209.55.246.0/23",
        "209.55.253.0/24",
        "209.55.254.0/24",
        "209.172.5.0/24",
        "209.236.210.0/24",
        "210.1.232.0/23",
        "211.188.26.0/23",
        "212.6.39.0/24",
        "212.104.128.0/24",
        "216.19.107.0/24",
        "216.74.106.0/24",
        "216.132.75.0/24",
        "216.163.179.0/24",
        "216.183.79.0/24",
        "216.224.121.0/24",
        "217.180.16.0/23",
        "218.33.92.0/22",
        "222.167.32.0/22",
        "222.167.230.0/24",
            ]),
        ],
    ),
    "cloudfront": Service(
        ip_file="cloudfront_ip.lst",
        sources=[Source("cloudfront")],
    ),
    # tiktok сюда не включён: не нашёл официального ASN/фида, которому доверяю
    # в автоматическом режиме. Список tiktok_ip.lst скрипт не трогает —
    # обновляй руками либо добавь Source("resolve") и свой tiktok_domains.lst.
}


def build_service(name: str, svc: Service) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for src in svc.sources:
        if src.kind == "resolve":
            if not svc.domains_file:
                log.warning("  %s: source=resolve, но domains_file не задан — пропуск", name)
                continue
            domains = read_lst(BASE_DIR / svc.domains_file)
            domains = [d.lstrip("*.") for d in domains]  # "*.example.com" -> "example.com"
            if not domains:
                log.warning("  %s: %s пуст или не найден", name, svc.domains_file)
                continue
            nets += resolve_domains(domains)
        elif src.kind == "asn":
            nets += asn_to_networks(src.asn)
        elif src.kind == "cloudflare":
            nets += fetch_cloudflare()
        elif src.kind == "cloudfront":
            nets += fetch_cloudfront()
        elif src.kind == "github_meta":
            nets += fetch_github_meta()
        elif src.kind == "google_full":
            nets += fetch_google_ranges()
        elif src.kind == "extra_cidrs":
            for c in src.cidrs:
                try:
                    nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    log.warning("  битый CIDR в extra_cidrs: %s", c)
        elif src.kind == "official_url":
            if "telegram.org" in src.url:
                nets += fetch_telegram_official()
            else:
                r = requests.get(src.url, timeout=HTTP_TIMEOUT, headers={"User-Agent": UA})
                r.raise_for_status()
                for l in r.text.splitlines():
                    l = l.strip()
                    if l:
                        try:
                            net = ipaddress.ip_network(l, strict=False)
                        except ValueError:
                            continue
                        if isinstance(net, ipaddress.IPv4Network):
                            nets.append(net)
        else:
            log.warning("  неизвестный тип источника: %s", src.kind)
    return nets


BASE_DIR = Path(__file__).resolve().parent / "lists"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="список сервисов через запятую, напр. telegram,youtube")
    ap.add_argument("--dry-run", action="store_true", help="только показать диф, файлы не менять")
    ap.add_argument("--dir", default=None, help="папка с .lst-файлами (по умолчанию — ./lists рядом со скриптом)")
    ap.add_argument("--list", action="store_true", help="показать сервисы и рецепты, ничего не делать")
    args = ap.parse_args()

    global BASE_DIR
    if args.dir:
        BASE_DIR = Path(args.dir).resolve()
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    if args.list:
        for name, svc in SERVICES.items():
            recipe = ", ".join(s.kind if not s.asn else f"{s.kind}(AS{s.asn})" for s in svc.sources)
            print(f"{name:12s} -> {svc.ip_file:25s} [{recipe}]")
        return

    names = list(SERVICES) if not args.only else [n.strip() for n in args.only.split(",")]
    unknown = [n for n in names if n not in SERVICES]
    if unknown:
        log.error("неизвестные сервисы: %s (см. --list)", ", ".join(unknown))
        sys.exit(1)

    log.info("папка с файлами: %s", BASE_DIR)
    for name in names:
        svc = SERVICES[name]
        log.info("[%s]", name)
        nets = build_service(name, svc)
        if not nets:
            log.warning("  %s: не удалось получить ни одной подсети, файл не трогаю", name)
            continue
        new_lines = finalize(nets)
        old_lines = read_lst(BASE_DIR / svc.ip_file)
        diff_report(svc.ip_file, old_lines, new_lines)
        if not args.dry_run:
            write_lst(BASE_DIR / svc.ip_file, new_lines)

    log.info("готово.")


if __name__ == "__main__":
    main()
