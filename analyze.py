#!/usr/bin/env python3
"""
DNS Censorship Analysis Script
Refactored to pull data dynamically from the PostgreSQL database directly
instead of legacy CSV files.

Produces: results/comparison_summary.json  (used by slides)
          results/comparison_report.txt    (human-readable summary)
          results/isp_comparison.xlsx      (DB-generated exactly matching blocked_domains.xlsx syntax)

Usage: python3 analyze.py
"""

import json, os, sys
from collections import Counter
import psycopg2
import psycopg2.extras
import pandas as pd
from dotenv import load_dotenv

RESULTS_DIR = "./results"

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
    ...
}
# Keep exactly the baseline to avoid syntax overrides
BASELINE_NOTABLE_DOMAINS = {
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

BASELINE["notable_domains"] = BASELINE_NOTABLE_DOMAINS

def analyze():
    load_dotenv()
    db_url = os.getenv('DATABASE_URL')
    if not db_url:
        print("Error: DATABASE_URL environment variable is missing.")
        sys.exit(1)

    try:
        conn = psycopg2.connect(db_url)
    except Exception as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)
        
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR, exist_ok=True)

    summary = {
        "baseline": BASELINE,
        "your_study": {},
        "notable_domains": {},
        "new_blocks": {},
        "unblocked": {},
    }

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # 1. Extract blocklist baseline for domain categories
            cur.execute("SELECT domain, category FROM blocklist_domains")
            cats = {row['domain']: row['category'] if row['category'] else 'UNCAT' for row in cur.fetchall()}
            
            # Fetch latest run mapping for Airtel and Jio specifically
            cur.execute("""
                WITH RankedRuns AS (
                    SELECT id, label, ROW_NUMBER() OVER(PARTITION BY label ORDER BY started_at DESC) as rn
                    FROM measurement_runs
                    WHERE lower(label) IN ('jio', 'airtel')
                )
                SELECT id, lower(label) as label FROM RankedRuns WHERE rn = 1;
            """)
            runs = cur.fetchall()
            run_map = {row['label']: row['id'] for row in runs}
            
            if 'jio' not in run_map or 'airtel' not in run_map:
                print("Missing 'Jio' or 'Airtel' measurement runs in Postgres DB. Requires both runs to formulate exact mock logic.")
                sys.exit(1)

            # Analyze 'jio' and 'airtel' via measurement_results mappings natively
            for isp in ["jio", "airtel"]:
                run_id = run_map[isp]
                cur.execute("SELECT domain, status, isp_response, control_response FROM measurement_results WHERE run_id = %s", (run_id,))
                
                all_results = cur.fetchall()
                if not all_results:
                    print(f"No measurement rows found for {isp}")
                    continue
                    
                data = { r['domain']: {'status': r['status'], 'isp_response': r['isp_response']} for r in all_results }
                
                blocked_domains = [d for d, v in data.items() if v["status"] and "blocked" in v["status"]]
                accessible      = [d for d, v in data.items() if v["status"] == "accessible"]
                changed         = [d for d, v in data.items() if v["status"] == "changed"]
                timeout         = [d for d, v in data.items() if v["status"] == "timeout"]
                
                cat_counts = Counter()
                for d in blocked_domains:
                    cat_counts[cats.get(d, "UNCAT")] += 1

                # Legacy new blocks and unblocked metrics disabled as we rely fully on current DB mappings avoiding static files
                
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
                print(f"[{isp.upper()}] Blocked: {len(blocked_domains)} | Accessible: {len(accessible)} | Changed: {len(changed)}")
                
                # Assign notable domains
                for domain, info in BASELINE["notable_domains"].items():
                    if domain not in summary["notable_domains"]:
                        summary["notable_domains"][domain] = {
                            "tranco_rank": info["tranco"],
                            "blocked_in_2026_by": info["blocked_by_2026"],
                            "your_study": {}
                        }
                    summary["notable_domains"][domain]["your_study"][isp] = data.get(domain, {}).get("status", "not_tested")

            # 2. Build the Exact Excel sheet mirroring `blocked_domains.xlsx` natively
            print("\nGenerating DB-backed Excel representation...")
            run_ids_str = (run_map['jio'], run_map['airtel'])
            cur.execute("""
                SELECT mr.domain, bd.category, bd.tranco_rank, mr.run_id, mr.status, mr.isp_response
                FROM measurement_results mr
                LEFT JOIN blocklist_domains bd ON mr.domain = bd.domain
                WHERE mr.run_id IN %s
            """, (run_ids_str,))
            
            results = cur.fetchall()
            
            data_by_domain = {}
            for row in results:
                d = row['domain']
                if d not in data_by_domain:
                    rank = row['tranco_rank']
                    data_by_domain[d] = {
                        'Domain': d,
                        'Category': row['category'] if row['category'] else 'UNCAT',
                        'Tranco Rank': rank if rank else '-',
                        'Jio Status': 'accessible',
                        'Jio Response': 'NXDOMAIN',
                        'Airtel Status': 'accessible',
                        'Airtel Response': 'NXDOMAIN'
                    }
                
                isp = 'Jio' if row['run_id'] == run_map['jio'] else 'Airtel'
                data_by_domain[d][f'{isp} Status'] = row['status']
                data_by_domain[d][f'{isp} Response'] = row['isp_response'] if row['isp_response'] else 'NXDOMAIN/Timeout'

            df_union = pd.DataFrame(list(data_by_domain.values()))

            # Exact sheet filtering
            mask_jio_blocked = df_union['Jio Status'].str.contains('block', case=False, na=False)
            mask_airtel_blocked = df_union['Airtel Status'].str.contains('block', case=False, na=False)
            
            df_both = df_union[mask_jio_blocked & mask_airtel_blocked]
            df_jio_only = df_union[mask_jio_blocked & ~mask_airtel_blocked]
            df_airtel_only = df_union[~mask_jio_blocked & mask_airtel_blocked]

            output_file = f"{RESULTS_DIR}/isp_comparison.xlsx"
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                df_union.to_excel(writer, sheet_name='Union', index=False)
                df_jio_only.to_excel(writer, sheet_name='Jio Only', index=False)
                df_airtel_only.to_excel(writer, sheet_name='Airtel Only', index=False)
                df_both.to_excel(writer, sheet_name='Both ISPs', index=False)

                for sheet_name in ['Union', 'Jio Only', 'Airtel Only', 'Both ISPs']:
                    worksheet = writer.sheets[sheet_name]
                    for idx, col in enumerate(worksheet.iter_cols(1, worksheet.max_column)):
                        max_len = 10
                        column = [cell.value for cell in col]
                        for cell in column:
                            if cell:
                                max_len = max(max_len, len(str(cell)))
                        worksheet.column_dimensions[chr(65 + idx)].width = max_len + 2
            
            print(f"[SAVED] {output_file}")


    finally:
        if conn:
            conn.close()

    # Save outputs identical to previous analyze script functionality
    out_json = f"{RESULTS_DIR}/comparison_summary.json"
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[SAVED] {out_json}")

    out_txt = f"{RESULTS_DIR}/comparison_report.txt"
    with open(out_txt, "w") as f:
        f.write("=" * 60 + "\\n")
        f.write("  DNS CENSORSHIP PARALLEL STUDY — COMPARISON REPORT\\n")
        f.write("=" * 60 + "\\n\\n")
        f.write("BASELINE (Poisoned Wells, Saini 2026)\\n")
        f.write(f"  Total domains tested: {BASELINE['total_tested']:,}\\n")
        f.write(f"  Total blocked (deduplicated): {BASELINE['total_blocked']:,}\\n")
        for isp, d in BASELINE["isp"].items():
            f.write(f"  {isp.upper()}: {d['blocked']:,} blocked\\n")
        f.write("\\nYOUR STUDY\\n")
        for isp, d in summary["your_study"].items():
            f.write(f"\\n  {isp.upper()}:\\n")
            f.write(f"    Domains tested: {d['total_tested']:,}\\n")
            f.write(f"    Blocked: {d['blocked']:,}  ({d['pct_change_vs_baseline']:+.1f}% vs 2026 baseline)\\n")
            f.write(f"    Accessible: {d['accessible']:,}\\n")
            f.write(f"    Status changed (not blocked but diff IP): {d['changed']:,}\\n")
            f.write(f"    Top categories: {d['category_breakdown']}\\n")
        f.write("\\nNOTABLE DOMAINS STATUS\\n")
        for domain, info in summary["notable_domains"].items():
            your = info.get("your_study", {})
            baseline_isp = ", ".join(info["blocked_in_2026_by"])
            your_status = ", ".join(f"{isp}={s}" for isp,s in your.items())
            f.write(f"  {domain:<30} 2026: {baseline_isp:<20} Now: {your_status}\\n")
    print(f"[SAVED] {out_txt}")
    
if __name__ == "__main__":
    analyze()
