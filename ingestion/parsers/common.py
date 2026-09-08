"""Utilidades compartidas para convertir texto libre de los reportes CSV
(dinero, porcentajes, fechas, numeros dentro de una frase) a tipos nativos.
"""

import re
from datetime import datetime
from typing import Optional


def parse_money(text: Optional[str]) -> Optional[float]:
    """'$32m' -> 32000000.0 | '$381,000' -> 381000.0 | '$0.87m' -> 870000.0"""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    match = re.search(r"\$?([\d,.]+)\s*(m|k)?", text, re.IGNORECASE)
    if not match:
        return None
    number = float(match.group(1).replace(",", ""))
    suffix = (match.group(2) or "").lower()
    if suffix == "m":
        number *= 1_000_000
    elif suffix == "k":
        number *= 1_000
    return round(number, 2)


def parse_percent(text: Optional[str]) -> Optional[float]:
    """'89.50%' -> 89.5 | '3.1% of revenue' -> 3.1 | 'N/A' -> None"""
    if text is None:
        return None
    match = re.search(r"([\d.]+)\s*%", text)
    if not match:
        return None
    return float(match.group(1))


def parse_int_in_text(text: Optional[str], label: str) -> Optional[int]:
    """extract_int('Compliant: 26, Non-compliant: 0', 'Non-compliant') -> 0"""
    if text is None:
        return None
    match = re.search(rf"{re.escape(label)}\s*:\s*(\d+)", text, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def parse_report_date(text: Optional[str]):
    """'July 07, 2026' or '19/08/2026' -> datetime.date, o None si no aplica."""
    if text is None:
        return None
    text = text.strip()
    for fmt in ("%B %d, %Y", "%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def parse_ranked_item(item: str):
    """'1. Deploy SPF, DKIM & DMARC (monitor to reject)' -> (1, 'Deploy SPF...')"""
    match = re.match(r"\s*(\d+)\.\s*(.+)", item)
    if not match:
        return None, item.strip()
    return int(match.group(1)), match.group(2).strip()
