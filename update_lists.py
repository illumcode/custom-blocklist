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
    """Резолвит список доменов в /24-подсети (соседние IP того же сервиса)."""
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
                nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))
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
    """Дедуп + схлопывание смежных сетей + вырезание DNS-резолверов + сортировка."""
    nets = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]  # на случай, если источник подсунет IPv6
    uniq = list({n for n in nets})
    collapsed = list(ipaddress.collapse_addresses(uniq)) if uniq else []
    out = []
    for n in collapsed:
        if any(n.overlaps(r) for r in RESOLVER_NETS):
            # Точечно исключаем адрес резолвера, а не всю сеть с ним.
            pieces = [n]
            for r in RESOLVER_NETS:
                pieces = [p for piece in pieces for p in (
                    list(piece.address_exclude(r)) if piece.overlaps(r) and r.subnet_of(piece)
                    else ([] if piece.subnet_of(r) else [piece])
                )]
            out += pieces
        else:
            out.append(n)
    out = list(ipaddress.collapse_addresses(set(out)))
    out.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in out]


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
    kind: str                # "resolve" | "asn" | "cloudflare" | "cloudfront" | "official_url"
    asn: int | None = None
    url: str | None = None


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
        sources=[Source("resolve")],
    ),
    "gemini": Service(
        ip_file="gemini_ip_fix.lst",
        domains_file="gemini_domains.lst",
        sources=[Source("resolve")],
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
        sources=[Source("cloudflare")],
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
