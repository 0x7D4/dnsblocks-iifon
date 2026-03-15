#!/usr/bin/env python3
"""
DNS Censorship Analysis Script
Run after measure.sh for both ISPs.
Produces: results/comparison_summary.json  (used by slides)
          results/comparison_report.txt    (human-readable summary)

Usage: python3 analyze.py
"""

import csv, json, os, sys
from collections import defaultdict, Counter

RESULTS_DIR = "./results"
BLOCKLIST_CSV = f"{RESULTS_DIR}/compiled_blocklist.csv"

# ── Baseline from Poisoned Wells (2026) ──────────────────────────────────────
BASELINE = {
    "total_tested":  294_480_735,
    "total_blocked": 43_083,
    "isp": {
        "jio":     {"blocked": 15_245, "block_sig": "49.44.79.236"},
        "airtel":  {"blocked": 27_649, "block_sig": "13.127.247.216"},
        "act":     {"blocked": 14_173, "block_sig": "49.205.171.201"},
        "mtnl":    {"blocked": 20_085, "block_sig": "59.185.3.14"},
        "you":     {"blocked": 14_052, "block_sig": "203.109.71.154"},
        "connect": {"blocked":  9_414, "block_sig": "202.164.51.25"},
    },
    "categories": {
        "MOV":  20_986, "UNCAT": 10_027, "PORN": 2_953, "FILE": 2_188,
        "GMB":  1_906,  "LIVE":  1_224,  "MISC": 1_168, "MAL":  921,
        "MILX": 171,    "IPTM":  521,
    },
    "notable_domains": {
        "tiktokcdn.com":     {"tranco": 28,  "blocked_by_2026": ["jio"]},
        "tiktokv.com":       {"tranco": 67,  "blocked_by_2026": ["jio"]},
        "bit.ly":            {"tranco": 71,  "blocked_by_2026": ["mtnl"]},
        "ax-msedge.net":     {"tranco": 62,  "blocked_by_2026": ["mtnl"]},
        "lencr.org":         {"tranco": 159, "blocked_by_2026": ["mtnl"]},
        "t.me":              {"tranco": 116, "blocked_by_2026": ["mtnl"]},
        "discord.com":       {"tranco": 251, "blocked_by_2026": ["mtnl"]},
        "slack.com":         {"tranco": 250, "blocked_by_2026": ["mtnl"]},
        "dailymotion.com":   {"tranco": 347, "blocked_by_2026": ["airtel"]},
        "slideshare.net":    {"tranco": 317, "blocked_by_2026": ["you"]},
        "scribd.com":        {"tranco": 486, "blocked_by_2026": ["you"]},
        "academia.edu":      {"tranco": 842, "blocked_by_2026": ["you"]},
        "mega.co.nz":        {"tranco": 464, "blocked_by_2026": ["mtnl"]},
        "dropboxapi.com":    {"tranco": 1229,"blocked_by_2026": ["mtnl"]},
        "surfshark.com":     {"tranco": 1048,"blocked_by_2026": ["mtnl"]},
        "videolan.org":      {"tranco": None,"blocked_by_2026": ["act"]},
        "thekashmirwalla.com":{"tranco":None,"blocked_by_2026": ["jio","airtel","act","mtnl","you","connect"]},
    }
}

# ── Load blocklist for category info ─────────────────────────────────────────
def load_blocklist():
    cats = {}
    if not os.path.exists(BLOCKLIST_CSV):
        print(f"[WARN] Blocklist CSV not found at {BLOCKLIST_CSV}")
        return cats
    with open(BLOCKLIST_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain","").strip().lower()
            cat    = row.get("category","UNCAT").strip()
            cats[domain] = cat
    return cats

# ── Load ISP results ──────────────────────────────────────────────────────────
def load_results(isp):
    path = f"{RESULTS_DIR}/{isp}_results.csv"
    if not os.path.exists(path):
        return None
    data = {}
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"].strip().lower()
            data[domain] = {
                "isp_response": row["isp_response"],
                "control_response": row["control_response"],
                "status": row["status"],
            }
    return data

# ── Main analysis ─────────────────────────────────────────────────────────────
def analyze():
    cats = load_blocklist()
    summary = {
        "baseline": BASELINE,
        "your_study": {},
        "notable_domains": {},
        "new_blocks": {},
        "unblocked": {},
    }

    all_blocked_domains = set()

    for isp in ["jio", "airtel"]:
        data = load_results(isp)
        if data is None:
            print(f"[INFO] No results for {isp} yet — skipping")
            continue

        blocked_domains = [d for d, v in data.items() if "blocked" in v["status"]]
        accessible      = [d for d, v in data.items() if v["status"] == "accessible"]
        changed         = [d for d, v in data.items() if v["status"] == "changed"]
        timeout         = [d for d, v in data.items() if v["status"] == "timeout"]
        all_blocked_domains.update(blocked_domains)

        # Category breakdown for blocked
        cat_counts = Counter()
        for d in blocked_domains:
            cat_counts[cats.get(d, "UNCAT")] += 1

        # Compare to baseline blocklist — what's newly blocked vs unblocked
        baseline_isp_domains = set()
        with open(BLOCKLIST_CSV) as f:
            reader = csv.DictReader(f)
            for row in reader:
                isp_col = isp.upper()
                if isp_col in row and row[isp_col].strip().upper() == "Y":
                    baseline_isp_domains.add(row["domain"].strip().lower())
                # Fallback: if column structure is different, just use all
        if not baseline_isp_domains:
            # If CSV doesn't have per-ISP columns, skip diff
            pass

        your_blocked_set = set(blocked_domains)
        newly_blocked    = sorted(your_blocked_set - baseline_isp_domains)[:50] if baseline_isp_domains else []
        now_unblocked    = sorted(baseline_isp_domains - your_blocked_set)[:50] if baseline_isp_domains else []

        summary["your_study"][isp] = {
            "total_tested":    len(data),
            "blocked":         len(blocked_domains),
            "accessible":      len(accessible),
            "changed":         len(changed),
            "timeout":         len(timeout),
            "category_breakdown": dict(cat_counts.most_common(10)),
            "pct_change_vs_baseline": round(
                (len(blocked_domains) - BASELINE["isp"][isp]["blocked"])
                / BASELINE["isp"][isp]["blocked"] * 100, 1
            ) if BASELINE["isp"][isp]["blocked"] else 0,
        }
        if newly_blocked:  summary["new_blocks"][isp]  = newly_blocked
        if now_unblocked:  summary["unblocked"][isp]   = now_unblocked
        print(f"[{isp.upper()}] Blocked: {len(blocked_domains)} | Accessible: {len(accessible)} | Changed: {len(changed)}")

    # Notable domains check
    for isp in ["jio", "airtel"]:
        data = load_results(isp)
        if data is None:
            continue
        for domain, info in BASELINE["notable_domains"].items():
            if domain not in summary["notable_domains"]:
                summary["notable_domains"][domain] = {
                    "tranco_rank": info["tranco"],
                    "blocked_in_2026_by": info["blocked_by_2026"],
                    "your_study": {}
                }
            if domain in data:
                summary["notable_domains"][domain]["your_study"][isp] = data[domain]["status"]
            else:
                summary["notable_domains"][domain]["your_study"][isp] = "not_tested"

    # Save
    out_json = f"{RESULTS_DIR}/comparison_summary.json"
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[SAVED] {out_json}")

    # Human-readable report
    out_txt = f"{RESULTS_DIR}/comparison_report.txt"
    with open(out_txt, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  DNS CENSORSHIP PARALLEL STUDY — COMPARISON REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write("BASELINE (Poisoned Wells, Saini 2026)\n")
        f.write(f"  Total domains tested: {BASELINE['total_tested']:,}\n")
        f.write(f"  Total blocked (deduplicated): {BASELINE['total_blocked']:,}\n")
        for isp, d in BASELINE["isp"].items():
            f.write(f"  {isp.upper()}: {d['blocked']:,} blocked\n")
        f.write("\nYOUR STUDY\n")
        for isp, d in summary["your_study"].items():
            f.write(f"\n  {isp.upper()}:\n")
            f.write(f"    Domains tested: {d['total_tested']:,}\n")
            f.write(f"    Blocked: {d['blocked']:,}  ({d['pct_change_vs_baseline']:+.1f}% vs 2026 baseline)\n")
            f.write(f"    Accessible: {d['accessible']:,}\n")
            f.write(f"    Status changed (not blocked but diff IP): {d['changed']:,}\n")
            f.write(f"    Top categories: {d['category_breakdown']}\n")
        f.write("\nNOTABLE DOMAINS STATUS\n")
        for domain, info in summary["notable_domains"].items():
            your = info.get("your_study", {})
            baseline_isp = ", ".join(info["blocked_in_2026_by"])
            your_status = ", ".join(f"{isp}={s}" for isp,s in your.items())
            f.write(f"  {domain:<30} 2026: {baseline_isp:<20} Now: {your_status}\n")
    print(f"[SAVED] {out_txt}")
    print(f"\nOpen {out_txt} for human-readable summary.")
    return summary

if __name__ == "__main__":
    analyze()
