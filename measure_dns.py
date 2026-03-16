#!/usr/bin/env python3
"""
measure_dns.py — ISP-Agnostic DNS Censorship Measurement Tool
══════════════════════════════════════════════════════════════
Uses dnspython for all DNS queries. Works on any ISP, any OS.
Detects your ISP's DNS resolver as the default gateway (instead of system
DNS settings) and compares its responses against a control resolver (1.1.1.1)
to identify DNS-based blocking.

Optionally stores every piece of raw data in PostgreSQL (--db flag).

Database configuration (via .env file or environment variables):
    DB_USER=your_user
    DB_PASSWORD=your_password
    DB_NAME=your_database
    DB_HOST=localhost
    DB_PORT=5432

Usage:
    python measure_dns.py                           # auto-detect resolver (gateway)
    python measure_dns.py --resolver 192.168.1.1    # specify resolver
    python measure_dns.py --label MyISP             # custom label for output
    python measure_dns.py --db                       # persist to PostgreSQL (uses env vars)
    python measure_dns.py --analyze --db             # cross-ISP analysis

Requirements:
    pip install dnspython tqdm
    pip install psycopg2-binary   (only if using --db)
"""

import argparse
import csv
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.request
from collections import Counter, namedtuple
from datetime import datetime, timezone
from pathlib import Path

# ── Load .env file (DB_USER, DB_PASSWORD, etc.) ──────────────────────────────
try:
    from dotenv import load_dotenv
    # Look for .env next to the script, then in cwd
    _env_path = Path(__file__).resolve().parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
    else:
        load_dotenv()  # tries cwd
except ImportError:
    # python-dotenv not installed — fall back to manual .env parsing
    _env_path = Path(__file__).resolve().parent / ".env"
    if not _env_path.exists():
        _env_path = Path(".env")
    if _env_path.exists():
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())

# ── Auto-install core dependencies ────────────────────────────────────────────
def _ensure(pkg, import_name=None):
    import_name = import_name or pkg
    try:
        return __import__(import_name)
    except ImportError:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "-q"],
            capture_output=True,
        )
        return __import__(import_name)

_ensure("dnspython", "dns.resolver")
_ensure("tqdm")

import dns.resolver
import dns.exception
import dns.rdatatype
import dns.flags
import dns.rcode
from tqdm import tqdm

# ── Constants ─────────────────────────────────────────────────────────────────
CONTROL_RESOLVER = "1.1.1.1"
RESULTS_DIR      = Path("results")

WORKERS    = 10
BATCH_SIZE = 50
BATCH_DELAY= 0.05
TIMEOUT    = 5

BLOCKLIST_URL = "https://raw.githubusercontent.com/qurbat/dnsblocks.in/main/data/compiled_blocklist.csv"

PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
}

KNOWN_BLOCK_IPS = {
    "49.44.79.236":   "Jio",
    "13.127.247.216": "Airtel",
    "49.205.171.201": "ACT",
    "59.185.3.14":    "MTNL",
    "203.109.71.154": "You Broadband",
    "202.164.51.25":  "Connect",
}


# ══════════════════════════════════════════════════════════════════════════════
#  QueryResult — rich DNS response object
# ══════════════════════════════════════════════════════════════════════════════

class QueryResult:
    """
    Rich DNS query result capturing all raw data:
      - ip:          first A record (or status string like NXDOMAIN)
      - all_ips:     list of all A record IPs
      - ttl:         TTL of the first answer (or None)
      - cname_chain: list of CNAMEs traversed before A record
      - flags:       dict of DNS header flags (AA, RD, RA, TC, AD, CD)
      - rcode:       response code string (NOERROR, NXDOMAIN, SERVFAIL, ...)
      - time_ms:     query round-trip time in milliseconds
    """
    __slots__ = ("ip", "all_ips", "ttl", "cname_chain", "flags", "rcode", "time_ms")

    def __init__(self, ip, all_ips=None, ttl=None, cname_chain=None,
                 flags=None, rcode=None, time_ms=None):
        self.ip          = ip
        self.all_ips     = all_ips or []
        self.ttl         = ttl
        self.cname_chain = cname_chain or []
        self.flags       = flags or {}
        self.rcode       = rcode or ""
        self.time_ms     = time_ms

    def __str__(self):
        return self.ip

    def __eq__(self, other):
        if isinstance(other, str):
            return self.ip == other
        if isinstance(other, QueryResult):
            return self.ip == other.ip
        return NotImplemented

    def __hash__(self):
        return hash(self.ip)


# ══════════════════════════════════════════════════════════════════════════════
#  DNS query via dnspython (enhanced)
# ══════════════════════════════════════════════════════════════════════════════

def query_a(resolver_ip, domain, timeout=None):
    """
    Query a single domain for its A record via a specific resolver.
    Returns a QueryResult with full raw data.
    """
    t = timeout or TIMEOUT
    start = time.perf_counter()

    try:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [resolver_ip]
        res.timeout     = t
        res.lifetime    = t

        answer = res.resolve(domain, "A")
        elapsed = (time.perf_counter() - start) * 1000

        # Extract all A records
        all_ips = [rdata.address for rdata in answer]
        first_ip = all_ips[0] if all_ips else "NOANSWER"

        # TTL from first rrset
        ttl = answer.rrset.ttl if answer.rrset else None

        # CNAME chain
        cname_chain = []
        if answer.response.answer:
            for rrset in answer.response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    for rdata in rrset:
                        cname_chain.append(str(rdata.target).rstrip("."))

        # DNS header flags
        resp = answer.response
        flag_int = resp.flags
        flags = {
            "AA": bool(flag_int & dns.flags.AA),
            "RD": bool(flag_int & dns.flags.RD),
            "RA": bool(flag_int & dns.flags.RA),
            "TC": bool(flag_int & dns.flags.TC),
            "AD": bool(flag_int & dns.flags.AD),
            "CD": bool(flag_int & dns.flags.CD),
        }
        rcode = dns.rcode.to_text(resp.rcode())

        return QueryResult(
            ip=first_ip, all_ips=all_ips, ttl=ttl,
            cname_chain=cname_chain, flags=flags,
            rcode=rcode, time_ms=round(elapsed, 2),
        )

    except dns.resolver.NXDOMAIN:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(ip="NXDOMAIN", rcode="NXDOMAIN", time_ms=round(elapsed, 2))
    except dns.resolver.NoAnswer:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(ip="NOANSWER", rcode="NOANSWER", time_ms=round(elapsed, 2))
    except dns.resolver.NoNameservers:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(ip="SERVFAIL", rcode="SERVFAIL", time_ms=round(elapsed, 2))
    except dns.resolver.Timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(ip="TIMEOUT", rcode="TIMEOUT", time_ms=round(elapsed, 2))
    except dns.exception.DNSException:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(ip="ERROR", rcode="ERROR", time_ms=round(elapsed, 2))
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(ip="TIMEOUT", rcode="TIMEOUT", time_ms=round(elapsed, 2))


# ══════════════════════════════════════════════════════════════════════════════
#  Resolver detection — now uses default gateway (not system DNS)
# ══════════════════════════════════════════════════════════════════════════════

def _is_valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _detect_gateway_linux():
    """Get default gateway IP on Linux."""
    try:
        # Try `ip route show default`
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # typical output: default via 192.168.1.1 dev eth0
            match = re.search(r"default via ([\d.]+)", result.stdout)
            if match:
                return match.group(1)
        # Fallback to `route -n`
        result = subprocess.run(
            ["route", "-n"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "0.0.0.0":
                return parts[1]  # gateway
    except Exception:
        pass
    return None


def _detect_gateway_macos():
    """Get default gateway IP on macOS."""
    try:
        # `route -n get default` gives gateway
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5
        )
        # output contains "gateway: 192.168.1.1"
        match = re.search(r"gateway:\s*([\d.]+)", result.stdout)
        if match:
            return match.group(1)
        # Alternative: netstat -rn
        result = subprocess.run(
            ["netstat", "-rn"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "default" in line:
                parts = line.split()
                # typical: default 192.168.1.1 ...
                if len(parts) >= 2:
                    return parts[1]
    except Exception:
        pass
    return None


def _detect_gateway_windows():
    """Get default gateway IP on Windows."""
    try:
        # PowerShell: Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty NextHop
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            ip = result.stdout.strip()
            if _is_valid_ip(ip):
                return ip
        # Fallback: route print
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=5
        )
        # Look for line with 0.0.0.0 and gateway
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                # typical: 0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.100
                if len(parts) >= 3:
                    ip = parts[2] if len(parts) > 2 else None
                    if ip and _is_valid_ip(ip):
                        return ip
    except Exception:
        pass
    return None


def detect_resolver():
    """
    Detect ISP's DNS resolver as the default gateway.
    If gateway detection fails, fall back to system DNS settings with a warning.
    """
    system = platform.system().lower()
    gateway = None

    if system == "windows":
        gateway = _detect_gateway_windows()
    elif system == "darwin":
        gateway = _detect_gateway_macos()
    else:  # linux and others
        gateway = _detect_gateway_linux()

    if gateway:
        print(f"[INFO] Using default gateway {gateway} as DNS resolver (assumed ISP DNS).")
        return gateway

    # Fallback to original detection (system DNS) with a warning
    print("[WARN] Could not detect default gateway. Falling back to system DNS resolver detection.")
    resolvers = []
    if system == "windows":
        resolvers = _detect_windows()
    else:
        resolvers = _detect_resolvconf()
        if not resolvers and system == "darwin":
            resolvers = _detect_macos_scutil()
    for r in resolvers:
        if r not in PUBLIC_DNS:
            return r
    return resolvers[0] if resolvers else None


# ── Original system DNS detection functions (kept for fallback) ───────────────
def _detect_windows():
    servers = []
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-DnsClientServerAddress -AddressFamily IPv4 | "
             "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
             "Select-Object -ExpandProperty ServerAddresses"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                ip = line.strip()
                if ip and _is_valid_ip(ip):
                    servers.append(ip)
    except Exception:
        pass
    if not servers:
        try:
            result = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True, timeout=10,
            )
            for match in re.findall(r"DNS Servers.*?:\s*([\d.]+)", result.stdout):
                if _is_valid_ip(match):
                    servers.append(match)
        except Exception:
            pass
    return servers


def _detect_resolvconf():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    if _is_valid_ip(parts[1]):
                        servers.append(parts[1])
    except Exception:
        pass
    return servers


def _detect_macos_scutil():
    servers = []
    try:
        result = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, timeout=10,
        )
        for match in re.findall(r"nameserver\[\d+\]\s*:\s*([\d.]+)", result.stdout):
            if _is_valid_ip(match):
                servers.append(match)
    except Exception:
        pass
    return servers


# ══════════════════════════════════════════════════════════════════════════════
#  Network context detection (public IP + ASN)
# ══════════════════════════════════════════════════════════════════════════════

def detect_network_context():
    """Detect public IP and ASN using free APIs. Returns dict."""
    ctx = {"public_ip": None, "asn": None, "asn_org": None, "country": None}
    try:
        resp = urllib.request.urlopen("https://ipinfo.io/json", timeout=5)
        data = json.loads(resp.read().decode())
        ctx["public_ip"] = data.get("ip")
        org = data.get("org", "")
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            ctx["asn"] = parts[0]
            ctx["asn_org"] = parts[1] if len(parts) > 1 else ""
        ctx["country"] = data.get("country")
    except Exception:
        pass
    return ctx


# ══════════════════════════════════════════════════════════════════════════════
#  Block signature detection (thepiratebay.org)
# ══════════════════════════════════════════════════════════════════════════════

def detect_block_signature(resolver):
    """Query thepiratebay.org to detect the ISP's block IP."""
    print(f"\n[DETECT] Probing thepiratebay.org for block signature...")
    isp_r  = query_a(resolver, "thepiratebay.org")
    ctrl_r = query_a(CONTROL_RESOLVER, "thepiratebay.org")

    print(f"  Via ISP resolver ({resolver})  : {isp_r}")
    print(f"  Via {CONTROL_RESOLVER} (control)          : {ctrl_r}")

    if isp_r.ip in ("NXDOMAIN", "NOANSWER", "TIMEOUT", "SERVFAIL", "ERROR"):
        print(f"[DETECT] ISP returned {isp_r} — cannot determine block IP.")
        return None
    if isp_r.ip == ctrl_r.ip:
        print(f"[DETECT] Same result as control — ISP may not block this domain.")
        return None

    known = KNOWN_BLOCK_IPS.get(isp_r.ip, "")
    print(f"\n[DETECT] Block signature detected: {isp_r.ip}")
    if isp_r.ttl is not None:
        print(f"         TTL: {isp_r.ttl}")
    if isp_r.cname_chain:
        print(f"         CNAME chain: {' → '.join(isp_r.cname_chain)}")
    if known:
        print(f"         Matches known ISP: {known}")

    return isp_r.ip


# ══════════════════════════════════════════════════════════════════════════════
#  Classification
# ══════════════════════════════════════════════════════════════════════════════

def classify(isp_resp, ctrl_resp, block_ip=None):
    """Classify a domain's censorship status by comparing ISP vs control.

    Status values (in evaluation order):
      blocked          — ISP returned the known block IP signature
      unresolvable     — both resolvers failed (domain broken globally, not an ISP block)
      blocked_nxdomain — ISP returns NXDOMAIN but control resolves fine
      blocked_servfail — ISP returns SERVFAIL but control resolves fine
      changed          — both return real IPs but different (possible undetected block or geo-diff)
      timeout          — ISP timed out / errored but control succeeded (or both timed out → unresolvable)
      accessible       — same real IP from both, or no evidence of interference
    """
    NON_IP = ("NXDOMAIN", "NOANSWER", "TIMEOUT", "SERVFAIL", "ERROR")
    isp_ip  = isp_resp.ip  if isinstance(isp_resp, QueryResult) else isp_resp
    ctrl_ip = ctrl_resp.ip if isinstance(ctrl_resp, QueryResult) else ctrl_resp

    # 1. Known block-IP signature — highest confidence, check first
    if block_ip and isp_ip == block_ip:
        return "blocked"

    # 2. Both resolvers failed — domain is globally unresolvable, not an ISP block.
    #    Must be checked before the individual NXDOMAIN/SERVFAIL block checks so that
    #    SERVFAIL/SERVFAIL, NXDOMAIN/NXDOMAIN, SERVFAIL/NOANSWER etc. are never
    #    misclassified as blocked.
    if isp_ip in NON_IP and ctrl_ip in NON_IP:
        return "unresolvable"

    # 3. ISP lies with NXDOMAIN while control resolves fine — ISP is blocking
    if isp_ip == "NXDOMAIN" and ctrl_ip not in NON_IP:
        return "blocked_nxdomain"

    # 4. ISP returns SERVFAIL while control resolves fine — ISP is blocking.
    #    Uses the full NON_IP set (previously used an incomplete tuple that missed
    #    SERVFAIL and NOANSWER, causing false positives).
    if isp_ip == "SERVFAIL" and ctrl_ip not in NON_IP:
        return "blocked_servfail"

    # 5. Both return real IPs but different — possible undetected block (ISP redirects
    #    to an unknown block page IP) or legitimate geographic/CDN difference.
    #    Check the top changed IPs after a run to spot hidden block signatures.
    if isp_ip not in NON_IP and ctrl_ip not in NON_IP and isp_ip != ctrl_ip:
        return "changed"

    # 6. ISP side failed (timeout / no answer / error) while control succeeded
    if isp_ip in ("TIMEOUT", "NOANSWER", "ERROR"):
        return "timeout"

    # 7. Both returned the same real IP, or remaining edge cases with no evidence
    #    of interference
    return "accessible"


# ══════════════════════════════════════════════════════════════════════════════
#  Blocklist loading & downloading
# ══════════════════════════════════════════════════════════════════════════════

def download_blocklist(dest):
    """Download compiled_blocklist.csv from GitHub if not present."""
    print(f"[INFO] Downloading blocklist from GitHub...")
    print(f"       {BLOCKLIST_URL}")
    try:
        urllib.request.urlretrieve(BLOCKLIST_URL, dest)
        with open(dest, encoding="utf-8") as f:
            header = f.readline().lower()
        if "domain" in header:
            lines = sum(1 for _ in open(dest, encoding="utf-8"))
            print(f"[OK]   Downloaded ({lines:,} lines) → {dest}")
            return True
        else:
            print(f"[WARN] Downloaded file doesn't look like a valid blocklist CSV.")
            return False
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        return False


def load_blocklist_csv(path):
    """Load full blocklist CSV including all columns. Returns (domains, rows)."""
    rows = []
    domains = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip().lower()
            if domain:
                domains.append(domain)
                rows.append({k.strip(): v.strip() for k, v in row.items()})
    seen = set()
    unique_domains = []
    unique_rows = []
    for d, r in zip(domains, rows):
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)
            unique_rows.append(r)
    return unique_domains, unique_rows


def load_plain_list(path):
    """Load domains from a plain text file (one per line)."""
    domains = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            d = line.strip().lower()
            if d and not d.startswith("#"):
                domains.append(d)
    return list(dict.fromkeys(domains))


# ══════════════════════════════════════════════════════════════════════════════
#  Measurement engine
# ══════════════════════════════════════════════════════════════════════════════

def run_measurement(domains, resolver, label):
    """
    Query all domains against a resolver with bounded concurrency.
    Returns dict: domain → QueryResult
    """
    total   = len(domains)
    results = {}
    batches = [domains[i:i+BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

    bar = tqdm(
        total=total,
        unit=" domains",
        ncols=78,
        desc=f"  {label[:22]:<22}",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
    )

    for batch in batches:
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {ex.submit(query_a, resolver, d): d for d in batch}
            for f in concurrent.futures.as_completed(futures):
                domain = futures[f]
                results[domain] = f.result()
        bar.update(len(batch))
        time.sleep(BATCH_DELAY)

    bar.close()
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  PostgreSQL — Connection from environment variables
# ══════════════════════════════════════════════════════════════════════════════

def construct_db_connection():
    """Build PostgreSQL connection string from environment variables."""
    user = os.environ.get("DB_USER")
    password = os.environ.get("DB_PASSWORD")
    dbname = os.environ.get("DB_NAME")
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")

    if not all([user, password, dbname]):
        return None

    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


SCHEMA_SQL = """
-- ── Measurement tables ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS measurement_runs (
    id              SERIAL PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    resolver_ip     TEXT NOT NULL,
    control_resolver TEXT NOT NULL,
    label           TEXT NOT NULL,
    block_ip        TEXT,
    total_domains   INTEGER,
    workers         INTEGER,
    batch_size      INTEGER,
    timeout_sec     INTEGER,
    blocklist_source TEXT,
    public_ip       TEXT,
    asn             TEXT,
    asn_org         TEXT,
    country         TEXT
);

CREATE TABLE IF NOT EXISTS dns_queries (
    id              SERIAL PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES measurement_runs(id),
    domain          TEXT NOT NULL,
    resolver_ip     TEXT NOT NULL,
    query_type      TEXT NOT NULL CHECK (query_type IN ('isp', 'control')),
    response        TEXT,
    all_responses   TEXT[],
    ttl             INTEGER,
    cname_chain     TEXT[],
    flags           JSONB,
    rcode           TEXT,
    response_time_ms REAL,
    queried_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_queries_run   ON dns_queries(run_id);
CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain);

CREATE TABLE IF NOT EXISTS measurement_results (
    id              SERIAL PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES measurement_runs(id),
    domain          TEXT NOT NULL,
    isp_response    TEXT,
    control_response TEXT,
    status          TEXT NOT NULL,
    block_ip_used   TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run    ON measurement_results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_status ON measurement_results(status);

CREATE TABLE IF NOT EXISTS run_summary (
    id              SERIAL PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES measurement_runs(id),
    status          TEXT NOT NULL,
    count           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blocklist_domains (
    id              SERIAL PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE,
    category        TEXT,
    tranco_rank     TEXT,
    loaded_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON blocklist_domains(domain);

CREATE TABLE IF NOT EXISTS blocklist_isp_flags (
    id              SERIAL PRIMARY KEY,
    domain          TEXT NOT NULL REFERENCES blocklist_domains(domain),
    isp_name        TEXT NOT NULL,
    is_blocked      BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(domain, isp_name)
);

-- ── Analysis tables ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS category_breakdowns (
    id              SERIAL PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES measurement_runs(id),
    category        TEXT NOT NULL,
    blocked_count   INTEGER NOT NULL,
    total_in_category INTEGER,
    percentage      REAL
);

CREATE TABLE IF NOT EXISTS expired_blocks (
    id              SERIAL PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES measurement_runs(id),
    domain          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_expired_run ON expired_blocks(run_id);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id              SERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS analysis_members (
    id              SERIAL PRIMARY KEY,
    analysis_id     INTEGER NOT NULL REFERENCES analysis_runs(id),
    run_id          INTEGER NOT NULL REFERENCES measurement_runs(id)
);

CREATE TABLE IF NOT EXISTS cross_isp_overlap (
    id              SERIAL PRIMARY KEY,
    analysis_id     INTEGER NOT NULL REFERENCES analysis_runs(id),
    run_a_id        INTEGER NOT NULL REFERENCES measurement_runs(id),
    run_b_id        INTEGER NOT NULL REFERENCES measurement_runs(id),
    label_a         TEXT,
    label_b         TEXT,
    only_a          INTEGER NOT NULL,
    only_b          INTEGER NOT NULL,
    both_blocked    INTEGER NOT NULL,
    union_blocked   INTEGER NOT NULL,
    overlap_pct     REAL
);

CREATE TABLE IF NOT EXISTS access_asymmetry (
    id              SERIAL PRIMARY KEY,
    analysis_id     INTEGER NOT NULL REFERENCES analysis_runs(id),
    run_a_id        INTEGER NOT NULL REFERENCES measurement_runs(id),
    run_b_id        INTEGER NOT NULL REFERENCES measurement_runs(id),
    label_a         TEXT,
    label_b         TEXT,
    blocked_a_accessible_b INTEGER NOT NULL,
    blocked_b_accessible_a INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blocklist_changes (
    id              SERIAL PRIMARY KEY,
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    run_old_id      INTEGER NOT NULL REFERENCES measurement_runs(id),
    run_new_id      INTEGER NOT NULL REFERENCES measurement_runs(id),
    label           TEXT,
    domain          TEXT NOT NULL,
    change_type     TEXT NOT NULL CHECK (change_type IN ('added', 'removed'))
);
CREATE INDEX IF NOT EXISTS idx_changes_runs ON blocklist_changes(run_old_id, run_new_id);
"""


def db_connect():
    """Connect to PostgreSQL using environment variables."""
    connstr = construct_db_connection()
    if not connstr:
        print("[ERROR] Database connection failed: Missing DB_USER, DB_PASSWORD, or DB_NAME environment variables.")
        return None

    try:
        import psycopg2
    except ImportError:
        print("[INFO] Installing psycopg2-binary...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "psycopg2-binary", "-q"],
            capture_output=True,
        )
        import psycopg2

    try:
        conn = psycopg2.connect(connstr)
        conn.autocommit = False
        return conn
    except Exception as e:
        print(f"[ERROR] Could not connect to database: {e}")
        return None


def db_init(conn):
    """Create all tables if they don't exist."""
    with conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)
    conn.commit()
    print("[DB]   Schema initialized.")


def db_insert_run(conn, resolver, control, label, block_ip,
                  total_domains, workers, batch_size, timeout_sec,
                  blocklist_source, net_ctx):
    """Insert a measurement_run row. Returns run_id."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO measurement_runs
                (resolver_ip, control_resolver, label, block_ip,
                 total_domains, workers, batch_size, timeout_sec,
                 blocklist_source, public_ip, asn, asn_org, country)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
        """, (resolver, control, label, block_ip,
              total_domains, workers, batch_size, timeout_sec,
              blocklist_source,
              net_ctx.get("public_ip"), net_ctx.get("asn"),
              net_ctx.get("asn_org"), net_ctx.get("country")))
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def db_complete_run(conn, run_id):
    """Set completed_at for a run."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE measurement_runs SET completed_at = NOW() WHERE id = %s",
            (run_id,))
    conn.commit()


def db_upsert_blocklist(conn, bl_rows):
    """Bulk-upsert blocklist domains + ISP flags."""
    if not bl_rows:
        return
    import psycopg2.extras

    # Insert domains
    with conn.cursor() as cur:
        domain_data = [
            (r.get("domain", "").lower(),
             r.get("category", ""),
             r.get("tranco_rank", ""))
            for r in bl_rows
        ]
        psycopg2.extras.execute_values(
            cur,
            """INSERT INTO blocklist_domains (domain, category, tranco_rank)
               VALUES %s
               ON CONFLICT (domain) DO UPDATE
               SET category = EXCLUDED.category, tranco_rank = EXCLUDED.tranco_rank""",
            domain_data,
            page_size=1000,
        )

        # ISP flags
        isp_cols = ["ACT", "AIRTEL", "CONNECT", "JIO", "MTNL", "YOU"]
        flag_data = []
        for r in bl_rows:
            domain = r.get("domain", "").lower()
            for col in isp_cols:
                val = r.get(col, "0")
                if val == "1":
                    flag_data.append((domain, col, True))

        if flag_data:
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO blocklist_isp_flags (domain, isp_name, is_blocked)
                   VALUES %s
                   ON CONFLICT (domain, isp_name) DO UPDATE
                   SET is_blocked = EXCLUDED.is_blocked""",
                flag_data,
                page_size=1000,
            )
    conn.commit()
    print(f"[DB]   Blocklist: {len(bl_rows):,} domains upserted.")


def db_insert_queries(conn, run_id, isp_results, ctrl_results, resolver, control):
    """Bulk-insert raw DNS query results."""
    import psycopg2.extras

    rows = []
    for domain, qr in isp_results.items():
        rows.append((
            run_id, domain, resolver, "isp",
            qr.ip, qr.all_ips or [], qr.ttl,
            qr.cname_chain or [],
            json.dumps(qr.flags) if qr.flags else None,
            qr.rcode, qr.time_ms,
        ))
    for domain, qr in ctrl_results.items():
        rows.append((
            run_id, domain, control, "control",
            qr.ip, qr.all_ips or [], qr.ttl,
            qr.cname_chain or [],
            json.dumps(qr.flags) if qr.flags else None,
            qr.rcode, qr.time_ms,
        ))

    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """INSERT INTO dns_queries
                (run_id, domain, resolver_ip, query_type,
                 response, all_responses, ttl,
                 cname_chain, flags, rcode, response_time_ms)
               VALUES %s""",
            rows,
            template="(%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)",
            page_size=1000,
        )
    conn.commit()
    print(f"[DB]   Queries: {len(rows):,} raw query records inserted.")


def db_insert_results(conn, run_id, classified, block_ip):
    """Bulk-insert classified measurement results."""
    import psycopg2.extras

    rows = [(run_id, d, isp_r, ctrl_r, st, block_ip)
            for d, isp_r, ctrl_r, st in classified]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """INSERT INTO measurement_results
                (run_id, domain, isp_response, control_response, status, block_ip_used)
               VALUES %s""",
            rows,
            page_size=1000,
        )
    conn.commit()
    print(f"[DB]   Results: {len(rows):,} classified records inserted.")


def db_insert_summary(conn, run_id, counts):
    """Insert run summary counts."""
    with conn.cursor() as cur:
        for status, count in counts.items():
            cur.execute(
                "INSERT INTO run_summary (run_id, status, count) VALUES (%s,%s,%s)",
                (run_id, status, count))
    conn.commit()


def db_insert_categories(conn, run_id, cat_counts):
    """Insert category breakdowns for blocked domains."""
    import psycopg2.extras
    rows = [(run_id, cat, cnt, None, None) for cat, cnt in cat_counts.items()]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """INSERT INTO category_breakdowns
                (run_id, category, blocked_count, total_in_category, percentage)
               VALUES %s""",
            rows,
        )
    conn.commit()


def db_insert_expired(conn, run_id, expired_domains):
    """Insert expired block domains."""
    import psycopg2.extras
    rows = [(run_id, d) for d in expired_domains]
    if rows:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                "INSERT INTO expired_blocks (run_id, domain) VALUES %s",
                rows, page_size=1000,
            )
        conn.commit()


def db_insert_changes(conn, run_old_id, run_new_id, label, added, removed):
    """Insert blocklist change records between two runs with the same label."""
    import psycopg2.extras
    rows = []
    for d in added:
        rows.append((run_old_id, run_new_id, label, d, "added"))
    for d in removed:
        rows.append((run_old_id, run_new_id, label, d, "removed"))
    if rows:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO blocklist_changes
                    (run_old_id, run_new_id, label, domain, change_type)
                   VALUES %s""",
                rows, page_size=1000,
            )
        conn.commit()
    return len(rows)


# ══════════════════════════════════════════════════════════════════════════════
#  Cross-ISP Analysis (--analyze)
# ══════════════════════════════════════════════════════════════════════════════

def run_analysis(conn):
    """
    Perform cross-ISP analysis using all completed measurement runs in the DB.
    Computes pairwise overlap, access asymmetry, and blocklist changes.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, label, resolver_ip, started_at, total_domains
            FROM measurement_runs
            WHERE completed_at IS NOT NULL
            ORDER BY started_at
        """)
        runs = cur.fetchall()

    if len(runs) < 2:
        print("[ANALYZE] Need at least 2 completed measurement runs for cross-ISP analysis.")
        print(f"          Found {len(runs)} run(s).")
        return

    print(f"\n{'='*60}")
    print(f"  Cross-ISP Analysis")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  Found {len(runs)} completed measurement runs:\n")
    for r in runs:
        print(f"    Run {r[0]:<4}  {r[1]:<20}  resolver={r[2]:<16}  "
              f"{r[3].strftime('%Y-%m-%d %H:%M')}  ({r[4]:,} domains)")

    # Create analysis run
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO analysis_runs (notes) VALUES (%s) RETURNING id",
            (f"Auto-analysis of {len(runs)} runs",))
        analysis_id = cur.fetchone()[0]
        for r in runs:
            cur.execute(
                "INSERT INTO analysis_members (analysis_id, run_id) VALUES (%s, %s)",
                (analysis_id, r[0]))
    conn.commit()

    # Load blocked sets for each run
    run_blocked = {}
    run_results = {}
    for r in runs:
        rid = r[0]
        with conn.cursor() as cur:
            cur.execute(
                "SELECT domain, status FROM measurement_results WHERE run_id = %s",
                (rid,))
            rows = cur.fetchall()
        run_blocked[rid] = {row[0] for row in rows if "blocked" in row[1]}
        run_results[rid] = {row[0]: row[1] for row in rows}

    # Pairwise comparisons
    print(f"\n{'─'*60}")
    print(f"  Pairwise Overlap & Asymmetry")
    print(f"{'─'*60}")

    for i, ra in enumerate(runs):
        for rb in runs[i+1:]:
            a_id, a_label = ra[0], ra[1]
            b_id, b_label = rb[0], rb[1]
            a_bl = run_blocked[a_id]
            b_bl = run_blocked[b_id]

            only_a = a_bl - b_bl
            only_b = b_bl - a_bl
            both   = a_bl & b_bl
            union  = a_bl | b_bl
            overlap = len(both) / len(union) * 100 if union else 0

            # Access asymmetry
            blk_a_acc_b = sum(1 for d in a_bl
                              if run_results[b_id].get(d) == "accessible")
            blk_b_acc_a = sum(1 for d in b_bl
                              if run_results[a_id].get(d) == "accessible")

            print(f"\n  {a_label} vs {b_label}:")
            print(f"    Only {a_label:<16}: {len(only_a):>6,}")
            print(f"    Both blocked        : {len(both):>6,}")
            print(f"    Only {b_label:<16}: {len(only_b):>6,}")
            print(f"    Union               : {len(union):>6,}")
            print(f"    Overlap             : {overlap:.1f}%")
            print(f"    Blocked {a_label}, accessible {b_label}: {blk_a_acc_b:,}")
            print(f"    Blocked {b_label}, accessible {a_label}: {blk_b_acc_a:,}")

            # Insert into DB
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO cross_isp_overlap
                        (analysis_id, run_a_id, run_b_id, label_a, label_b,
                         only_a, only_b, both_blocked, union_blocked, overlap_pct)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (analysis_id, a_id, b_id, a_label, b_label,
                      len(only_a), len(only_b), len(both), len(union), overlap))

                cur.execute("""
                    INSERT INTO access_asymmetry
                        (analysis_id, run_a_id, run_b_id, label_a, label_b,
                         blocked_a_accessible_b, blocked_b_accessible_a)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (analysis_id, a_id, b_id, a_label, b_label,
                      blk_a_acc_b, blk_b_acc_a))
            conn.commit()

    # Temporal diffs — compare runs with the same label
    label_runs = {}
    for r in runs:
        label_runs.setdefault(r[1], []).append(r)

    changes_found = False
    for label, lruns in label_runs.items():
        if len(lruns) < 2:
            continue
        # Compare latest two runs for each label
        old_run = lruns[-2]
        new_run = lruns[-1]
        old_bl = run_blocked[old_run[0]]
        new_bl = run_blocked[new_run[0]]
        added   = new_bl - old_bl
        removed = old_bl - new_bl

        if added or removed:
            if not changes_found:
                print(f"\n{'─'*60}")
                print(f"  Blocklist Changes (temporal diff)")
                print(f"{'─'*60}")
                changes_found = True

            print(f"\n  {label}: run {old_run[0]} → run {new_run[0]}")
            print(f"    Newly blocked  : {len(added):>6,}")
            print(f"    No longer blocked: {len(removed):>6,}")

            n = db_insert_changes(conn, old_run[0], new_run[0], label, added, removed)
            print(f"    [DB] {n} change records stored.")

    if not changes_found:
        print(f"\n  [INFO] No temporal blocklist changes detected.")

    print(f"\n{'='*60}")
    print(f"  Analysis complete (analysis_id={analysis_id})")
    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="ISP-agnostic DNS censorship measurement using dnspython",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python measure_dns.py                               # auto-detect everything (gateway)
  python measure_dns.py --resolver 192.168.1.1        # specify resolver
  python measure_dns.py --label BSNL                  # custom label
  python measure_dns.py --db                           # persist to PostgreSQL (uses DB_* env vars)
  python measure_dns.py --analyze --db                 # cross-ISP analysis

Database environment variables (in .env or system):
  DB_USER=your_user
  DB_PASSWORD=your_password
  DB_NAME=your_database
  DB_HOST=localhost
  DB_PORT=5432
        """,
    )
    parser.add_argument("--resolver", default=None,
                        help="ISP resolver IP (default: auto-detect gateway)")
    parser.add_argument("--control", default=CONTROL_RESOLVER,
                        help=f"Control resolver IP (default: {CONTROL_RESOLVER})")
    parser.add_argument("--label", default=None,
                        help="Label for this ISP (default: resolver IP)")
    parser.add_argument("--blocklist", default="results/compiled_blocklist.csv",
                        help="Path to domain list (auto-downloaded if missing)")
    parser.add_argument("--block-ip", default=None, dest="block_ip",
                        help="Known block IP (default: auto-detect via thepiratebay.org)")
    parser.add_argument("--workers", type=int, default=WORKERS,
                        help=f"Parallel query threads (default: {WORKERS})")
    parser.add_argument("--batch", type=int, default=BATCH_SIZE,
                        help=f"Domains per batch (default: {BATCH_SIZE})")
    parser.add_argument("--timeout", type=int, default=TIMEOUT,
                        help=f"Per-query timeout in seconds (default: {TIMEOUT})")
    parser.add_argument("--output", default=None,
                        help="Output CSV path (default: results/<label>_results.csv)")
    parser.add_argument("--skip-detect", action="store_true",
                        help="Skip block-IP auto-detection")
    parser.add_argument("--db", action="store_true",
                        help="Enable PostgreSQL storage (uses DB_* environment variables)")
    parser.add_argument("--analyze", action="store_true",
                        help="Run cross-ISP analysis on existing DB runs")
    args = parser.parse_args()

    # Apply tuning overrides
    import measure_dns as _self
    _self.WORKERS    = args.workers
    _self.BATCH_SIZE = args.batch
    _self.TIMEOUT    = args.timeout

    RESULTS_DIR.mkdir(exist_ok=True)

    # ── Database connection (optional) ────────────────────────────────────────
    conn = None
    if args.db:
        conn = db_connect()
        if conn:
            db_init(conn)
            print(f"[DB]   Connected to PostgreSQL.")
        else:
            print("[ERROR] Database connection failed. Check your DB_* environment variables.")
            sys.exit(1)

    # ── Analysis-only mode ────────────────────────────────────────────────────
    if args.analyze:
        if not conn:
            print("[ERROR] --analyze requires --db and valid DB_* environment variables")
            sys.exit(1)
        run_analysis(conn)
        conn.close()
        return

    # ── Resolver detection ────────────────────────────────────────────────────
    resolver = args.resolver
    if not resolver:
        resolver = detect_resolver()
    if not resolver:
        print("[ERROR] Could not detect DNS resolver.")
        print("        Use --resolver <IP> to specify manually.")
        sys.exit(1)

    if resolver in PUBLIC_DNS:
        print(f"[WARN] Resolver {resolver} is a well-known public DNS.")
        print(f"       Censorship measurement requires your ISP's resolver.")

    label   = args.label or resolver
    control = args.control
    block_ip = args.block_ip

    # ── Network context ───────────────────────────────────────────────────────
    print("[INFO] Detecting network context...")
    net_ctx = detect_network_context()

    # ── Banner ────────────────────────────────────────────────────────────────
    print("=" * 60)
    print(f"  DNS Censorship Measurement")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  ISP resolver : {resolver}")
    print(f"  Control      : {control}")
    print(f"  Label        : {label}")
    print(f"  Engine       : dnspython")
    print(f"  Workers      : {WORKERS}  |  Batch: {BATCH_SIZE}  |  Timeout: {TIMEOUT}s")
    if net_ctx["public_ip"]:
        print(f"  Public IP    : {net_ctx['public_ip']}")
    if net_ctx["asn"]:
        print(f"  ASN          : {net_ctx['asn']}  ({net_ctx.get('asn_org', '')})")
    if net_ctx["country"]:
        print(f"  Country      : {net_ctx['country']}")
    if conn:
        print(f"  Database     : ✓ connected")

    # ── Block signature detection ─────────────────────────────────────────────
    if not block_ip and not args.skip_detect:
        block_ip = detect_block_signature(resolver)

    if block_ip:
        known = KNOWN_BLOCK_IPS.get(block_ip, "")
        print(f"  Block IP     : {block_ip}" + (f"  ({known})" if known else ""))
    else:
        print(f"  Block IP     : none (will detect by comparison only)")

    # ── Load blocklist ────────────────────────────────────────────────────────
    blocklist_path = Path(args.blocklist)
    if not blocklist_path.exists():
        for alt in [Path("compiled_blocklist.csv"),
                    Path("results/compiled_blocklist.csv")]:
            if alt.exists():
                blocklist_path = alt
                break

    if not blocklist_path.exists():
        RESULTS_DIR.mkdir(exist_ok=True)
        blocklist_path = RESULTS_DIR / "compiled_blocklist.csv"
        if not download_blocklist(blocklist_path):
            print(f"[ERROR] Could not download blocklist.")
            sys.exit(1)
    else:
        lines = sum(1 for _ in open(blocklist_path, encoding="utf-8"))
        print(f"\n[INFO] Blocklist present ({lines:,} lines) → {blocklist_path}")

    # Detect format
    with open(blocklist_path, encoding="utf-8") as f:
        first_line = f.readline().strip().lower()

    bl_rows = []
    if "domain" in first_line and "," in first_line:
        domains, bl_rows = load_blocklist_csv(blocklist_path)
    else:
        domains = load_plain_list(blocklist_path)

    total = len(domains)
    print(f"[INFO] {total:,} unique domains to test.")
    if total == 0:
        print("[ERROR] No domains found.")
        sys.exit(1)

    # ── Upsert blocklist to DB ────────────────────────────────────────────────
    if conn and bl_rows:
        db_upsert_blocklist(conn, bl_rows)

    # ── Create DB run record ──────────────────────────────────────────────────
    run_id = None
    if conn:
        run_id = db_insert_run(
            conn, resolver, control, label, block_ip,
            total, WORKERS, BATCH_SIZE, TIMEOUT,
            str(blocklist_path), net_ctx,
        )
        print(f"[DB]   Measurement run created (id={run_id}).")

    # ── Run measurements ──────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  Pass 1 of 2 — ISP resolver ({resolver})")
    print(f"{'─'*60}")

    isp_results = run_measurement(domains, resolver, f"ISP ({label})")

    print(f"\n{'─'*60}")
    print(f"  Pass 2 of 2 — Control resolver ({control})")
    print(f"{'─'*60}")

    ctrl_results = run_measurement(domains, control, f"Control ({control})")

    # ── Insert raw queries to DB ──────────────────────────────────────────────
    if conn and run_id:
        db_insert_queries(conn, run_id, isp_results, ctrl_results, resolver, control)

    # ── Classify results ──────────────────────────────────────────────────────
    print("\n[INFO] Classifying results...")

    safe_label  = re.sub(r'[^\w.-]', '_', label)
    output_file = Path(args.output) if args.output else RESULTS_DIR / f"{safe_label}_results.csv"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    counts = Counter()
    classified = []  # (domain, isp_ip, ctrl_ip, status)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "isp_response", "control_response", "status"])
        for domain in domains:
            isp_r  = isp_results.get(domain, QueryResult("TIMEOUT"))
            ctrl_r = ctrl_results.get(domain, QueryResult("TIMEOUT"))
            status = classify(isp_r, ctrl_r, block_ip)
            writer.writerow([domain, isp_r.ip, ctrl_r.ip, status])
            counts[status] += 1
            classified.append((domain, isp_r.ip, ctrl_r.ip, status))

    total_blocked = counts["blocked"] + counts["blocked_nxdomain"] + counts["blocked_servfail"]

    # ── Insert classified results + summary to DB ─────────────────────────────
    if conn and run_id:
        db_insert_results(conn, run_id, classified, block_ip)
        db_insert_summary(conn, run_id, counts)

        # Category breakdowns for blocked domains
        if bl_rows:
            cat_map = {r["domain"].lower(): r.get("category", "?") for r in bl_rows}
            blocked_domains = [d for d, _, _, s in classified if "blocked" in s]
            cat_counts = Counter(cat_map.get(d, "?") for d in blocked_domains)
            db_insert_categories(conn, run_id, cat_counts)
            print(f"[DB]   Category breakdowns: {len(cat_counts)} categories stored.")

        # Expired blocks
        expired_domains = [
            d for d, isp_ip, ctrl_ip, s in classified
            if "blocked" in s and ctrl_ip in ("NXDOMAIN", "NOANSWER", "TIMEOUT")
        ]
        if expired_domains:
            db_insert_expired(conn, run_id, expired_domains)
            print(f"[DB]   Expired blocks: {len(expired_domains):,} domains stored.")

        # Temporal diffs vs previous run with same label
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id FROM measurement_runs
                WHERE label = %s AND id != %s AND completed_at IS NOT NULL
                ORDER BY started_at DESC LIMIT 1
            """, (label, run_id))
            prev = cur.fetchone()

        if prev:
            prev_id = prev[0]
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT domain FROM measurement_results WHERE run_id = %s AND status LIKE '%%blocked%%'",
                    (prev_id,))
                old_bl = {row[0] for row in cur.fetchall()}
            new_bl = {d for d, _, _, s in classified if "blocked" in s}
            added   = new_bl - old_bl
            removed = old_bl - new_bl
            if added or removed:
                n = db_insert_changes(conn, prev_id, run_id, label, added, removed)
                print(f"[DB]   Blocklist changes: +{len(added)} added, "
                      f"-{len(removed)} removed ({n} records).")

        # Mark run complete
        db_complete_run(conn, run_id)
        print(f"[DB]   Run {run_id} marked complete.")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"""
{'='*60}
  MEASUREMENT COMPLETE — {label}
{'='*60}
  Domains tested    : {total:>8,}
  ───────────────────────────────────
  Blocked (IP sig)  : {counts['blocked']:>8,}
  Blocked (NXDOM)   : {counts['blocked_nxdomain']:>8,}
  Blocked (SERVFAIL): {counts['blocked_servfail']:>8,}
  ───────────────────────────────────
  Total blocked     : {total_blocked:>8,}
  Accessible        : {counts['accessible']:>8,}
  Changed (diff IP) : {counts['changed']:>8,}
  Timeout           : {counts['timeout']:>8,}
  Unresolvable      : {counts['unresolvable']:>8,}
  ───────────────────────────────────
  Output            : {output_file}""")
    if conn and run_id:
        print(f"  DB run_id         : {run_id}")
    print(f"{'='*60}\n")

    # ── Top changed IPs ──────────────────────────────────────────────────────
    if counts["changed"] > 0:
        print("  [INFO] Top ISP-returned IPs for 'changed' domains:")
        changed_ips = Counter()
        for d, isp_ip, ctrl_ip, st in classified:
            if st == "changed":
                changed_ips[isp_ip] += 1
        for ip, cnt in changed_ips.most_common(10):
            known = KNOWN_BLOCK_IPS.get(ip, "")
            marker = f"  ← known: {known}" if known else ""
            print(f"         {ip:<20} {cnt:>6,} domains{marker}")
        print()
        if not block_ip and changed_ips:
            top_ip, top_cnt = changed_ips.most_common(1)[0]
            if top_cnt >= 5:
                print(f"  [TIP]  {top_ip} appears in {top_cnt} 'changed' responses.")
                print(f"         Re-run with: python measure_dns.py --block-ip {top_ip}\n")

    if conn:
        conn.close()


if __name__ == "__main__":
    main()
