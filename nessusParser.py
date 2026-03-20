import os
import re
import glob
import pandas as pd
import argparse

def process_csv(input_path, output_name, mapping_file):
    if not os.path.exists(input_path):
        print(f"Error: The directory '{input_path}' was not found.")
        return

    csv_pattern = os.path.join(input_path, "*.csv")
    all_filenames = glob.glob(csv_pattern)

    if not all_filenames:
        print(f"No CSV files found in: {input_path}")
        return
    
    df = pd.concat([pd.read_csv(f) for f in all_filenames])
    orig_df = df.copy() 

    # --- 1. HANDLE HOSTNAME MAPPING ---
    host_map = {}
    mapping_df_for_excel = None # Initialise for later use

    if mapping_file:
        mapping_path = os.path.join(input_path, mapping_file)
        if os.path.exists(mapping_path):
            with open(mapping_path, 'r') as f:
                for line in f:
                    if ':' not in line:
                        continue
                    parts = [p.strip() for p in line.split(':', 1)]
                    if len(parts) == 2 and parts[0]:
                        host_map[parts[0].lower()] = parts[1]
            
            if host_map:
                # Prepare the reference sheet data
                mapping_df_for_excel = pd.DataFrame(list(host_map.items()), columns=['Original Hostname', 'Mapped IP'])
                
                # Initialise stats
                stats = {ip: 0 for ip in host_map.values()}
                sorted_hosts = sorted(host_map.keys(), key=len, reverse=True)

                def replace_substrings(text):
                    if not isinstance(text, str) or text == 'nan':
                        return text
                    
                    for host in sorted_hosts:
                        ip = host_map[host]
                        pattern = rf'\b{re.escape(host)}\b'
                        
                        # Count matches for the summary
                        count = len(re.findall(pattern, text, flags=re.IGNORECASE))
                        if count > 0:
                            stats[ip] += count
                            text = re.sub(pattern, ip, text, flags=re.IGNORECASE)
                    return text

                df['Host'] = df['Host'].astype(str).apply(replace_substrings)
                
                print("\n" + "="*30)
                print("HOST REPLACEMENT SUMMARY")
                print("="*30)
                mapping_summary = pd.DataFrame(list(stats.items()), columns=['IP Address', 'Replacements'])
                print(mapping_summary[mapping_summary['Replacements'] > 0].to_string(index=False))
                print("="*30 + "\n")
        else:
            print(f"Warning: Mapping file {mapping_file} not found. Skipping replacement.")

    # --- 2. DATA PROCESSING LOGIC ---
    # Sort first so the "original" (first) entry for each combo is preserved
    df = df.sort_values(by=['Name', 'Host', 'Protocol', 'Port', 'Plugin ID', 'CVE'], ascending=True)
    df = df.drop_duplicates(subset=['Name', 'Host', 'Port', 'Plugin ID', 'CVE'])

    # Create a mask for rows where the Protocol/Port is already listed for that Name+Host, keeps the first occurrence and targets the repeats
    repeat_proto_port = df.duplicated(subset=['Name', 'Host', 'Protocol', 'Port'], keep='first')

    # Set Protocol and Port to empty strings for those repeats, use .loc to avoid SettingWithCopy warnings
    df[['Protocol', 'Port']] = df[['Protocol', 'Port']].astype(object)
    df.loc[repeat_proto_port, ['Protocol', 'Port']] = ""

    # Now mask the Host column to prevent repeating the IP
    df['Host'] = df['Host'].mask(df.duplicated(['Name', 'Host']))

    # Create the string. If Protocol/Port were blanked, this will result in "IP (/)" which will be cleaned in the next step.
    df['AffectedModules'] = (df['Host'].astype(str).str.strip() + 
                             " (" + df['Protocol'].astype(str).str.strip() + 
                             '/' + df['Port'].astype(str).str.strip() + ')')

    # Aggregate by finding name
    df = df.astype(str).groupby('Name').agg(lambda x: ', '.join(x.unique()))

    # --- 3. CLEANUP ---
    # Remove the "blank" module artifacts caused by the (/) logic
    df['AffectedModules'] = df['AffectedModules'].str.replace(r',?\s?nan\s?\(/+\)', '', regex=True)
    df['AffectedModules'] = df['AffectedModules'].str.replace(r'^\(/+\),?\s?', '', regex=True)
    
    # Cleanup for Host and formatting
    df['Host'] = df['Host'].replace({', nan' : ''}, regex=True)
    df['AffectedModules'] = df['AffectedModules'].replace({'\), nan \(' : ', '}, regex=True)
    df['AffectedModules'] = df['AffectedModules'].replace({'\), ' : ')\r\n'}, regex=True)
    
    # Final strip of any trailing commas or whitespace
    df = df.apply(lambda col: col.str.strip(', '))
    df = df.apply(lambda col: col.str.replace('nan', '-'))

    # --- 4. EXCEL WRITING ---
    if not output_name.endswith('.xlsx'):
        output_name += '.xlsx'
        
    output_path = os.path.join(input_path, output_name)
    
    with pd.ExcelWriter(output_path) as writer:  
        df.to_excel(writer, sheet_name='merge')
        orig_df.to_excel(writer, sheet_name='original', index=False)
        
        # Write the mapping reference sheet if it exists
        if mapping_df_for_excel is not None:
            mapping_df_for_excel.to_excel(writer, sheet_name='mapping_reference', index=False)

    print(f"Success! Report generated at: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Consolidate Nessus scan CSVs.")
    parser.add_argument("path", help="Path to the directory containing CSV / Mapping files.")
    parser.add_argument("-rh", "--replacehost", default=None, 
                        help="Name of text file with 'hostname:IP' pairs per line.")
    parser.add_argument("-o", "--output", default="merge.xlsx", 
                        help="Name of the output Excel file.")

    args = parser.parse_args()
    process_csv(args.path, args.output, args.replacehost)
