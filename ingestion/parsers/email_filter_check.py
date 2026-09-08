"""
Parser para 'Email-filter-check-*.csv'.

Este archivo no es una tabla plana: es un reporte exportado como filas
Seccion/Item/Detalle/Valor. Esta funcion lo interpreta y devuelve un
diccionario estructurado listo para cargar a BigQuery (tablas
email_filter_check_summary y email_filter_check_recommendations).
"""

import csv
import re
from typing import Any, Dict

from .common import parse_money, parse_percent, parse_int_in_text, parse_report_date, parse_ranked_item


def _read_rows(file_path: str):
    """Lee el CSV probando UTF-8 y, si falla, Latin-1 (encodings comunes en
    exports de herramientas de seguridad)."""
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with open(file_path, encoding=encoding, newline="") as f:
                rows = list(csv.DictReader(f))
            return rows, encoding
        except UnicodeDecodeError:
            continue
    raise ValueError(f"No se pudo leer '{file_path}' con UTF-8 ni Latin-1.")


def parse(file_path: str) -> Dict[str, Any]:
    rows, encoding = _read_rows(file_path)

    profile_name = None
    report_date = None
    domain = None
    summary: Dict[str, Any] = {}
    recommendations = []

    for row in rows:
        section = (row.get("Section") or "").strip()
        item = (row.get("Item") or "").strip()
        detail = (row.get("Detail") or "").strip()
        value = (row.get("Score / Value") or "").strip()
        cis = (row.get("CIS Alignment") or "").strip() or None

        if section == "Report":
            if item == "Profile":
                profile_name = detail
            elif item == "Report date":
                report_date = parse_report_date(detail)
            elif item == "Domain":
                domain = detail

        elif section == "Summary metrics":
            if item == "Total cyber risk":
                summary["total_cyber_risk_pct"] = parse_percent(detail)
                summary["total_cyber_risk_usd"] = parse_money(value)
            elif item == "EFC risk rating":
                summary["risk_rating"] = value
                summary["risk_rating_driver"] = detail
            elif item == "Email filter checks score":
                summary["email_filter_score_pct"] = parse_percent(value)
            elif item == "Secure configuration score":
                summary["secure_config_score_pct"] = parse_percent(value)

        elif section == "Email filter check results":
            if item == "Open relay":
                summary["open_relay_status"] = detail
                summary["open_relay_pct"] = parse_percent(value)
            elif "Sender Policy Framework" in item:
                summary["spf_status"] = detail
                summary["spf_pct"] = parse_percent(value)
            elif "Domain-Keys Identified Mail" in item:
                summary["dkim_status"] = detail
                summary["dkim_pct"] = parse_percent(value)
            elif "Domain-Message Authentication" in item:
                summary["dmarc_status"] = detail
                summary["dmarc_pct"] = parse_percent(value)

        elif section == "Email extension checks":
            if item.startswith("Obligatorio"):
                summary["mandatory_compliant"] = parse_int_in_text(detail, "Compliant")
                summary["mandatory_noncompliant"] = parse_int_in_text(detail, "Non-compliant")
                summary["mandatory_pct"] = parse_percent(value)
            elif item.startswith("Otras extensiones"):
                summary["other_ext_compliant"] = parse_int_in_text(detail, "Compliant")
                summary["other_ext_noncompliant"] = parse_int_in_text(detail, "Non-compliant")
                summary["other_ext_pct"] = parse_percent(value)
                match = re.search(r"\(([^)]+)\)", detail)
                summary["other_ext_failing_list"] = match.group(1) if match else None

        elif section == "Recommendations":
            if item == "Total opportunity":
                summary["total_risk_reduction_usd"] = parse_money(value)
            else:
                rank, text = parse_ranked_item(item)
                recommendations.append({
                    "rank": rank,
                    "recommendation": text,
                    "current_safeguard_pct": parse_percent(detail),
                    "risk_reduction_usd": parse_money(value),
                    "cis_control": cis,
                })

    return {
        "activity_type": "email_filter_check",
        "profile_name": profile_name,
        "report_date": report_date,
        "domain": domain,
        "encoding_used": encoding,
        "summary": summary,
        "recommendations": recommendations,
    }
