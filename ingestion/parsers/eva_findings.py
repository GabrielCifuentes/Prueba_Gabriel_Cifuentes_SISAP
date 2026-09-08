"""Parser para 'EVA-CIS76-Findings-With-Ports.csv' (tabla normal: una fila
por hallazgo de vulnerabilidad externa)."""

import csv
from typing import Any, Dict, List

from .common import parse_percent, parse_report_date, parse_yes_no


def _read_rows(file_path: str):
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with open(file_path, encoding=encoding, newline="") as f:
                rows = list(csv.DictReader(f))
            return rows, encoding
        except UnicodeDecodeError:
            continue
    raise ValueError(f"No se pudo leer '{file_path}' con UTF-8 ni Latin-1.")


def parse(file_path: str) -> Dict[str, Any]:
    raw_rows, encoding = _read_rows(file_path)
    findings: List[Dict[str, Any]] = []

    for row in raw_rows:
        findings.append({
            "host_ip": row.get("Host_IP", "").strip(),
            "host_name": row.get("Host_Name", "").strip(),
            "operating_system": row.get("Operating_System", "").strip(),
            "system_type": row.get("System_Type", "").strip(),
            "original_severity": row.get("Original_Severity", "").strip(),
            "adjusted_severity": row.get("Adjusted_Severity", "").strip(),
            "eol_reclassified": parse_yes_no(row.get("EOL_Reclassified")),
            "vulnerability_name": row.get("Vulnerability_Name", "").strip(),
            "synopsis": row.get("Synopsis", "").strip(),
            "exploit_available": parse_yes_no(row.get("Exploit_Available")),
            "eol_asset": parse_yes_no(row.get("EOL_Asset")),
            "asset_criticality_tier": row.get("Asset_Criticality_Tier", "").strip(),
            "vulnerability_age": row.get("Vulnerability_Age", "").strip(),
            "vuln_publication_date": parse_report_date(row.get("Vuln_Publication_Date")),
            "plugin_publication_date": parse_report_date(row.get("Plugin_Publication_Date")),
            "port": row.get("Port", "").strip(),
            "protocol": row.get("Protocol", "").strip(),
            "service": row.get("Service", "").strip(),
            "port_classification": row.get("Port_Classification", "").strip(),
            "scan_date": parse_report_date(row.get("Scan_Date")),
            "cis76_implementation_pct": parse_percent(row.get("CIS76_Implementation")),
            "external_vm_risk_level": row.get("External_VM_Risk_Level", "").strip(),
        })

    return {"encoding_used": encoding, "findings": findings}
