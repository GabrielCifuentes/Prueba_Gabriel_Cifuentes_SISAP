"""Parser para 'EVA-Top10-Recommendations-*.csv' (tabla normal: una fila
por recomendacion priorizada de la evaluacion de vulnerabilidades externas).

EOL_Asset y Exploit_Available se dejan como texto (no booleano): el archivo
trae valores mixtos como 'Yes (3 of 4 hosts)' o 'Unknown - Unauthenticated
Scan' que no son un simple Si/No.
"""

import csv
from typing import Any, Dict, List

from .common import parse_money


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
    rows: List[Dict[str, Any]] = []

    for row in raw_rows:
        rank_text = (row.get("Rank") or "").strip()
        rows.append({
            "rank": int(rank_text) if rank_text.isdigit() else None,
            "severity_addressed": row.get("Severity_Addressed", "").strip(),
            "recommendation": row.get("Recommendation", "").strip(),
            "description": row.get("Description", "").strip(),
            "affected_assets": row.get("Affected_Assets", "").strip(),
            "operating_system": row.get("Operating_System", "").strip(),
            "open_insecure_ports": row.get("Open_Insecure_Ports", "").strip(),
            "cve": row.get("CVE", "").strip(),
            "eol_asset": row.get("EOL_Asset", "").strip(),
            "exploit_available": row.get("Exploit_Available", "").strip(),
            "vulnerabilities_addressed": row.get("Vulnerabilities_Addressed", "").strip(),
            "risk_reduction_estimate_usd": parse_money(row.get("Risk_Reduction_Estimate")),
            "primary_loss_driver": row.get("Primary_Loss_Driver", "").strip(),
            "secondary_loss_driver": row.get("Secondary_Loss_Driver", "").strip(),
            "cis_control": row.get("CIS_Control", "").strip(),
            "remediation_complexity": row.get("Remediation_Complexity", "").strip(),
            "remediation_timeline": row.get("Remediation_Timeline", "").strip(),
        })

    return {"encoding_used": encoding, "recommendations": rows}
