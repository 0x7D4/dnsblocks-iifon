import os
import sys
import pandas as pd
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
import datetime

def main():
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

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Get latest runs for Jio and Airtel
            cur.execute("""
                WITH RankedRuns AS (
                    SELECT id, label, started_at, 
                           ROW_NUMBER() OVER(PARTITION BY label ORDER BY started_at DESC) as rn
                    FROM measurement_runs
                    WHERE lower(label) IN ('jio', 'airtel')
                )
                SELECT id, lower(label) as label FROM RankedRuns WHERE rn = 1;
            """)
            runs = cur.fetchall()

            run_map = {row['label']: row['id'] for row in runs}
            
            if 'jio' not in run_map or 'airtel' not in run_map:
                print("Could not find measurement runs for both 'Jio' and 'Airtel' in the database.")
                sys.exit(1)

            run_ids_str = (run_map['jio'], run_map['airtel'])

            print(f"\nFetching data for Jio and Airtel...")
            
            # Fetch data including Domain Category, Tranco Rank, Status, and Response
            query = """
                SELECT mr.domain, bd.category, bd.tranco_rank, mr.run_id, mr.status, mr.isp_response
                FROM measurement_results mr
                LEFT JOIN blocklist_domains bd ON mr.domain = bd.domain
                WHERE mr.run_id IN %s
            """
            
            cur.execute(query, (run_ids_str,))
            results = cur.fetchall()
            
            if not results:
                print("No measurement results found for the selected runs.")
                sys.exit(0)

            print(f"Processing {len(results)} individual records into dictionaries...")
            
            # Prepare data dictionaries manually to bypass pandas pivot alignment issues
            data_by_domain = {}
            for row in results:
                d = row['domain']
                if d not in data_by_domain:
                    rank = row['tranco_rank']
                    if not rank: rank = '-'
                    data_by_domain[d] = {
                        'Domain': d,
                        'Category': row['category'] if row['category'] else 'UNCAT',
                        'Tranco Rank': rank,
                        'Jio Status': 'accessible',
                        'Jio Response': 'NXDOMAIN',
                        'Airtel Status': 'accessible',
                        'Airtel Response': 'NXDOMAIN'
                    }
                
                # Update specific ISP column
                isp = 'Jio' if row['run_id'] == run_map['jio'] else 'Airtel'
                data_by_domain[d][f'{isp} Status'] = row['status']
                data_by_domain[d][f'{isp} Response'] = row['isp_response'] if row['isp_response'] else 'NXDOMAIN/Timeout'

            df_union = pd.DataFrame(list(data_by_domain.values()))

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ISP_Comparison_Report_{timestamp}.xlsx"
            print(f"Exporting to Excel: {output_file} ...")
            
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                
                # Filter specific sheets exactly like the requested mock
                mask_jio_blocked = df_union['Jio Status'].str.contains('block', case=False, na=False)
                mask_airtel_blocked = df_union['Airtel Status'].str.contains('block', case=False, na=False)
                
                df_both = df_union[mask_jio_blocked & mask_airtel_blocked]
                df_jio_only = df_union[mask_jio_blocked & ~mask_airtel_blocked]
                df_airtel_only = df_union[~mask_jio_blocked & mask_airtel_blocked]
                
                # Save to sheets
                df_union.to_excel(writer, sheet_name='Union', index=False)
                df_jio_only.to_excel(writer, sheet_name='Jio Only', index=False)
                df_airtel_only.to_excel(writer, sheet_name='Airtel Only', index=False)
                df_both.to_excel(writer, sheet_name='Both ISPs', index=False)

                sheets_to_format = ['Union', 'Jio Only', 'Airtel Only', 'Both ISPs']
                
                # Format columns natively
                for sheet_name in sheets_to_format:
                    worksheet = writer.sheets[sheet_name]
                    for idx, col in enumerate(worksheet.iter_cols(1, worksheet.max_column)):
                        max_len = 10
                        column = [cell.value for cell in col]
                        for cell in column:
                            if cell:
                                max_len = max(max_len, len(str(cell)))
                        worksheet.column_dimensions[chr(65 + idx)].width = max_len + 2

            print(f"Success! Professional comparison report created at '{os.path.abspath(output_file)}'.")
            
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
