"""
Parser para 'domain-account-review-report.csv'.

Igual que Email Filter Check, es un reporte en filas Section/Item/Value/Detail
(aqui sin encabezado de Section explicito en la mayoria de filas: viene vacio
y se identifica el bloque por el propio Item). Se recorre secuencialmente y
se detectan los items conocidos; los bloques de "Recommendations" si traen
Section explicito.
"""

import csv
from typing import Any, Dict

from .common import parse_money, parse_percent, parse_report_date, parse_ranked_item


def _read_rows(file_path: str):
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            with open(file_path, encoding=encoding, newline="") as f:
                rows = list(csv.DictReader(f))
            return rows, encoding
        except UnicodeDecodeError:
            continue
    raise ValueError(f"No se pudo leer '{file_path}' con UTF-8 ni Latin-1.")


def _to_int(text):
    if text is None or text == "":
        return None
    try:
        return int(str(text).replace(",", "").strip())
    except ValueError:
        return None


def parse(file_path: str) -> Dict[str, Any]:
    rows, encoding = _read_rows(file_path)

    profile_name = None
    report_date = None
    summary: Dict[str, Any] = {}
    recommendations = []

    active_accounts_for_mfa = None

    for row in rows:
        section = (row.get("Section") or "").strip()
        item = (row.get("Item") or "").strip()
        value = (row.get("Value") or "").strip()
        detail = (row.get("Detail") or "").strip()

        if item == "Report name":
            continue
        elif item == "Profile name":
            profile_name = value
        elif item == "Report date":
            report_date = parse_report_date(value)
        elif item == "Execution date":
            summary["execution_date"] = parse_report_date(value)
        elif item == "Total exposure":
            summary["total_exposure_usd"] = parse_money(value)
        elif item == "Domain Account Review risk rating":
            summary["risk_rating"] = value
            summary["risk_rating_driver"] = detail
        elif item == "Number of accounts evaluated":
            summary["accounts_evaluated"] = _to_int(value)
        elif item == "Accounts with passwords that do not expire":
            summary["accounts_pwd_never_expire"] = _to_int(value)
        elif item == "Accounts that do not require a password":
            summary["accounts_no_pwd_required"] = _to_int(value)
        elif item == "Dormant accounts +60 days and never used":
            summary["dormant_60d"] = _to_int(value)
        elif item == "Accounts without password change +90 days":
            summary["no_pwd_change_90d"] = _to_int(value)
        elif item == "Generic accounts":
            summary["generic_accounts"] = _to_int(value)
        elif item == "Default accounts":
            summary["default_accounts"] = _to_int(value)
        elif item == "Disabled accounts" and "disabled_accounts" not in summary:
            summary["disabled_accounts"] = _to_int(value)
        elif item == "Active accounts" and "active_accounts" not in summary:
            summary["active_accounts"] = _to_int(value)
            active_accounts_for_mfa = _to_int(value)
        elif item == "MFA Users - MFAUsers":
            summary["mfa_enrolled"] = _to_int(value)
            summary["mfa_enrolled_pct"] = parse_percent(detail)

        elif section == "Simulated Opportunity":
            if item == "Total opportunity":
                summary["total_opportunity_usd"] = parse_money(value)

        elif section == "Recommendations":
            rank, text = parse_ranked_item(item)
            recommendations.append({
                "rank": rank,
                "recommendation": text,
                "priority": value,
                "detail": detail,
            })

    return {
        "activity_type": "domain_account_review",
        "profile_name": profile_name,
        "report_date": report_date,
        "encoding_used": encoding,
        "summary": summary,
        "recommendations": recommendations,
    }
