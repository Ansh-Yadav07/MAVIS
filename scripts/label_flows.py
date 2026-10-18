"""Add a Label column to flows you extracted yourself with CICFlowMeter.

In a lab capture you know which machine attacked, so every flow to or from the
attacker IP gets the attack label and everything else is BENIGN:

    python scripts/label_flows.py flows.csv dataset/lab/portscan-day1.csv --attacker-ip 192.168.56.10 --label PortScan
    python scripts/label_flows.py normal.csv dataset/lab/benign-day1.csv   # no attacker: all BENIGN
"""
import argparse
import re
import sys

import pandas as pd

_IP_COLUMNS = {'srcip': 'src', 'sourceip': 'src', 'dstip': 'dst', 'destinationip': 'dst'}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('src', help='CICFlowMeter CSV')
    p.add_argument('dest', help='labelled CSV to write (put it under dataset/)')
    p.add_argument('--attacker-ip', action='append', default=[], help='repeat for several attackers')
    p.add_argument('--label', default='Attack', help="label for attacker flows, e.g. PortScan, 'DoS Hulk', SSH-Patator")
    a = p.parse_args()

    df = pd.read_csv(a.src, low_memory=False)
    ips = {}
    for c in df.columns:
        role = _IP_COLUMNS.get(re.sub(r'[^a-z]', '', c.lower()))
        if role:
            ips[role] = df[c].astype(str).str.strip()

    attack = pd.Series(False, index=df.index)
    if a.attacker_ip:
        if len(ips) < 2:
            sys.exit(f"no source/destination IP columns found in {a.src}; columns are {list(df.columns)[:10]}...")
        attack = ips['src'].isin(a.attacker_ip) | ips['dst'].isin(a.attacker_ip)

    df = df.drop(columns=[c for c in df.columns if c.strip().lower() == 'label'])
    df['Label'] = attack.map({True: a.label, False: 'BENIGN'})
    df.to_csv(a.dest, index=False)
    print(df['Label'].value_counts().to_string())


if __name__ == '__main__':
    main()
