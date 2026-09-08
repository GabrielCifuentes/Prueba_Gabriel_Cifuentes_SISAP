"""
Genera los informes PDF por actividad (Email Filter Check, Domain Account
Review, Evaluacion de Vulnerabilidades Externas) a partir de los datos ya
cargados en BigQuery.

Uso:
    python reports/generate_report.py --client cliente-demo --activity all
    python reports/generate_report.py --client cliente-demo --activity email_filter_check
"""

import argparse
import io
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.cloud import bigquery
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", str(PROJECT_ROOT / "credentials" / "gcp-service-account.json"))

from reports import charts, queries  # noqa: E402

PROJECT_ID = "prueba-gabriel-cifuentes-sisap"

STYLES = getSampleStyleSheet()
STYLES.add(ParagraphStyle(name="ReportTitle", fontSize=26, leading=32, alignment=1, spaceAfter=12))
STYLES.add(ParagraphStyle(name="ReportSubtitle", fontSize=14, leading=20, alignment=1, textColor=colors.HexColor("#555555")))
STYLES.add(ParagraphStyle(name="SectionHeading", fontSize=15, leading=20, spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#2C5F8A")))
STYLES.add(ParagraphStyle(name="KPILabel", fontSize=9, textColor=colors.HexColor("#666666")))
STYLES.add(ParagraphStyle(name="KPIValue", fontSize=16, leading=20, textColor=colors.HexColor("#1A1A1A")))
STYLES.add(ParagraphStyle(name="BodyTextSmall", fontSize=9, leading=12))

ACTIVITY_TITLES = {
    "email_filter_check": "Email Filter Check",
    "domain_account_review": "Domain Account Review",
    "external_vulnerability_assessment": "Evaluacion de Vulnerabilidades Externas",
}


def _fmt_date(value) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, (date, datetime)):
        return value.strftime("%d/%m/%Y")
    return str(value)


def _fmt_usd(value: Optional[float]) -> str:
    return f"${value:,.0f}" if value is not None else "N/A"


def _fmt_pct(value: Optional[float]) -> str:
    return f"{value:.1f}%" if value is not None else "N/A"


def _kpi_table(items: List[tuple]) -> Table:
    """items: lista de (etiqueta, valor) -- se acomodan en una fila de cajas."""
    cells = [[Paragraph(label, STYLES["KPILabel"]), Paragraph(value, STYLES["KPIValue"])] for label, value in items]
    row = [Table([[c[0]], [c[1]]], colWidths=[1.7 * inch]) for c in cells]
    t = Table([row], colWidths=[1.8 * inch] * len(items))
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F5F7FA")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _recommendations_table(rows: List[Dict[str, Any]], columns: List[tuple]) -> Table:
    """columns: lista de (encabezado, key, formatter_opcional)"""
    header = [c[0] for c in columns]
    data = [header]
    for row in rows:
        line = []
        for col in columns:
            key = col[1]
            formatter = col[2] if len(col) > 2 else (lambda v: "" if v is None else str(v))
            line.append(Paragraph(formatter(row.get(key)), STYLES["BodyTextSmall"]))
        data.append(line)

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C5F8A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _cover_page(activity_title: str, client_name: str, consultant_name: str, report_date) -> list:
    flow = [
        Spacer(1, 1.8 * inch),
        Paragraph("SISAP - Sistemas Aplicativos", STYLES["ReportSubtitle"]),
        Spacer(1, 0.3 * inch),
        Paragraph(f"Informe de Evaluacion<br/>{activity_title}", STYLES["ReportTitle"]),
        Spacer(1, 0.6 * inch),
        Paragraph(f"<b>Cliente:</b> {client_name}", STYLES["Normal"]),
        Spacer(1, 0.1 * inch),
        Paragraph(f"<b>Consultor:</b> {consultant_name}", STYLES["Normal"]),
        Spacer(1, 0.1 * inch),
        Paragraph(f"<b>Fecha de la revision:</b> {_fmt_date(report_date)}", STYLES["Normal"]),
        PageBreak(),
    ]
    return flow


def _image_flowable(png_bytes: bytes, width: float = 6.2 * inch) -> Image:
    img = Image(io.BytesIO(png_bytes))
    aspect = img.imageHeight / img.imageWidth
    img.drawWidth = width
    img.drawHeight = width * aspect
    return img


def build_email_filter_check_report(client: bigquery.Client, client_id: str, client_name: str,
                                     consultant_name: str, output_path: Path) -> Optional[Path]:
    history = queries.get_assessment_history(client, client_id, "email_filter_check")
    if not history:
        return None
    latest = history[-1]
    assessment_id = latest["assessment_id"]
    summary = queries.get_row(client, "email_filter_check_summary", assessment_id) or {}
    recommendations = queries.get_rows(client, "email_filter_check_recommendations", assessment_id, order_by="rank")

    flow = _cover_page(ACTIVITY_TITLES["email_filter_check"], client_name, consultant_name, latest["report_date"])

    flow.append(Paragraph("Resumen Ejecutivo", STYLES["SectionHeading"]))
    flow.append(_kpi_table([
        ("Nivel de riesgo", summary.get("risk_rating", "N/A")),
        ("Riesgo total", _fmt_usd(summary.get("total_cyber_risk_usd"))),
        ("Reduccion de riesgo estimada", _fmt_usd(summary.get("total_risk_reduction_usd"))),
        ("Score de filtrado", _fmt_pct(summary.get("email_filter_score_pct"))),
    ]))
    if summary.get("risk_rating_driver"):
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(f"<i>{summary['risk_rating_driver']}</i>", STYLES["BodyTextSmall"]))

    flow.append(Paragraph("Cumplimiento de controles de correo", STYLES["SectionHeading"]))
    chart = charts.compliance_bar_chart(
        ["Open Relay", "SPF", "DKIM", "DMARC"],
        [summary.get("open_relay_pct"), summary.get("spf_pct"), summary.get("dkim_pct"), summary.get("dmarc_pct")],
    )
    flow.append(_image_flowable(chart))

    if len(history) > 1:
        flow.append(Paragraph("Comparativo entre periodos", STYLES["SectionHeading"]))
        trend_labels = [_fmt_date(a["report_date"]) for a in history]
        trend_values = []
        for a in history:
            s = queries.get_row(client, "email_filter_check_summary", a["assessment_id"]) or {}
            trend_values.append(s.get("total_cyber_risk_usd") or 0)
        flow.append(_image_flowable(charts.trend_chart(trend_labels, trend_values, "Riesgo total ($) por periodo")))

    if recommendations:
        flow.append(Paragraph("Recomendaciones Priorizadas", STYLES["SectionHeading"]))
        chart = charts.horizontal_bar_chart(
            [f"#{r['rank']} {r['recommendation'][:40]}" for r in recommendations],
            [r.get("risk_reduction_usd") or 0 for r in recommendations],
            "Reduccion de riesgo estimada por recomendacion",
        )
        flow.append(_image_flowable(chart))
        flow.append(Spacer(1, 10))
        flow.append(_recommendations_table(recommendations, [
            ("#", "rank", str),
            ("Recomendacion", "recommendation"),
            ("Salvaguarda actual", "current_safeguard_pct", _fmt_pct),
            ("Reduccion de riesgo", "risk_reduction_usd", _fmt_usd),
            ("Control CIS", "cis_control"),
        ]))

    doc = SimpleDocTemplate(str(output_path), pagesize=LETTER,
                             topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    doc.build(flow)
    return output_path


def build_domain_account_review_report(client: bigquery.Client, client_id: str, client_name: str,
                                        consultant_name: str, output_path: Path) -> Optional[Path]:
    history = queries.get_assessment_history(client, client_id, "domain_account_review")
    if not history:
        return None
    latest = history[-1]
    assessment_id = latest["assessment_id"]
    summary = queries.get_row(client, "domain_account_review_summary", assessment_id) or {}
    recommendations = queries.get_rows(client, "domain_account_review_recommendations", assessment_id, order_by="rank")

    flow = _cover_page(ACTIVITY_TITLES["domain_account_review"], client_name, consultant_name, latest["report_date"])

    flow.append(Paragraph("Resumen Ejecutivo", STYLES["SectionHeading"]))
    flow.append(_kpi_table([
        ("Nivel de riesgo", summary.get("risk_rating", "N/A")),
        ("Exposicion total", _fmt_usd(summary.get("total_exposure_usd"))),
        ("Reduccion de riesgo estimada", _fmt_usd(summary.get("total_opportunity_usd"))),
        ("Cuentas evaluadas", str(summary.get("accounts_evaluated", "N/A"))),
    ]))
    if summary.get("risk_rating_driver"):
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(f"<i>{summary['risk_rating_driver']}</i>", STYLES["BodyTextSmall"]))

    flow.append(Paragraph("Factores de riesgo identificados", STYLES["SectionHeading"]))
    factor_labels = ["Cuentas genericas", "Cuentas por defecto", "Inactivas +60 dias",
                     "Password no expira", "Sin cambio pwd +90d", "Sin password requerido"]
    factor_values = [
        summary.get("generic_accounts") or 0, summary.get("default_accounts") or 0,
        summary.get("dormant_60d") or 0, summary.get("accounts_pwd_never_expire") or 0,
        summary.get("no_pwd_change_90d") or 0, summary.get("accounts_no_pwd_required") or 0,
    ]
    flow.append(_image_flowable(charts.horizontal_bar_chart(
        factor_labels, factor_values, "Cuentas afectadas por factor de riesgo", value_format="{:.0f}",
    )))

    if len(history) > 1:
        flow.append(Paragraph("Comparativo entre periodos", STYLES["SectionHeading"]))
        trend_labels = [_fmt_date(a["report_date"]) for a in history]
        trend_values = []
        for a in history:
            s = queries.get_row(client, "domain_account_review_summary", a["assessment_id"]) or {}
            trend_values.append(s.get("total_exposure_usd") or 0)
        flow.append(_image_flowable(charts.trend_chart(trend_labels, trend_values, "Exposicion total ($) por periodo")))

    if recommendations:
        flow.append(Paragraph("Recomendaciones Priorizadas", STYLES["SectionHeading"]))
        flow.append(_recommendations_table(recommendations, [
            ("#", "rank", str),
            ("Recomendacion", "recommendation"),
            ("Prioridad", "priority"),
            ("Detalle", "detail"),
        ]))

    doc = SimpleDocTemplate(str(output_path), pagesize=LETTER,
                             topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    doc.build(flow)
    return output_path


def build_external_vulnerability_report(client: bigquery.Client, client_id: str, client_name: str,
                                         consultant_name: str, output_path: Path) -> Optional[Path]:
    history = queries.get_assessment_history(client, client_id, "external_vulnerability_assessment")
    if not history:
        return None
    latest = history[-1]
    assessment_id = latest["assessment_id"]
    findings = queries.get_rows(client, "eva_findings", assessment_id)
    recommendations = queries.get_rows(client, "eva_top10_recommendations", assessment_id, order_by="rank")

    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("adjusted_severity") or "Desconocido"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_risk_reduction = sum(r.get("risk_reduction_estimate_usd") or 0 for r in recommendations)
    highest_severity = next((s for s in ["Critical", "High", "Medium", "Low"] if s in severity_counts), "N/A")

    flow = _cover_page(ACTIVITY_TITLES["external_vulnerability_assessment"], client_name, consultant_name, latest["report_date"])

    flow.append(Paragraph("Resumen Ejecutivo", STYLES["SectionHeading"]))
    flow.append(_kpi_table([
        ("Nivel de riesgo mas alto", highest_severity),
        ("Hallazgos totales", str(len(findings))),
        ("Reduccion de riesgo estimada", _fmt_usd(total_risk_reduction)),
        ("Activos afectados", str(len({f.get("host_ip") for f in findings}))),
    ]))

    flow.append(Paragraph("Hallazgos por severidad", STYLES["SectionHeading"]))
    flow.append(_image_flowable(charts.severity_bar_chart(severity_counts)))

    if len(history) > 1:
        flow.append(Paragraph("Comparativo entre periodos", STYLES["SectionHeading"]))
        trend_labels = [_fmt_date(a["report_date"]) for a in history]
        trend_values = [len(queries.get_rows(client, "eva_findings", a["assessment_id"])) for a in history]
        flow.append(_image_flowable(charts.trend_chart(trend_labels, trend_values, "Total de hallazgos por periodo", value_format="{:.0f}")))

    if recommendations:
        flow.append(Paragraph("Recomendaciones Priorizadas (Top 10)", STYLES["SectionHeading"]))
        chart = charts.horizontal_bar_chart(
            [f"#{r['rank']} {r['recommendation'][:40]}" for r in recommendations],
            [r.get("risk_reduction_estimate_usd") or 0 for r in recommendations],
            "Reduccion de riesgo estimada por recomendacion",
        )
        flow.append(_image_flowable(chart))
        flow.append(Spacer(1, 10))
        flow.append(_recommendations_table(recommendations, [
            ("#", "rank", str),
            ("Recomendacion", "recommendation"),
            ("Severidad", "severity_addressed"),
            ("Reduccion de riesgo", "risk_reduction_estimate_usd", _fmt_usd),
            ("Plazo", "remediation_timeline"),
        ]))

    doc = SimpleDocTemplate(str(output_path), pagesize=LETTER,
                             topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    doc.build(flow)
    return output_path


BUILDERS = {
    "email_filter_check": build_email_filter_check_report,
    "domain_account_review": build_domain_account_review_report,
    "external_vulnerability_assessment": build_external_vulnerability_report,
}


def main():
    parser = argparse.ArgumentParser(description="Genera informes PDF por actividad")
    parser.add_argument("--client", required=True, help="client_id (ej. cliente-demo)")
    parser.add_argument("--activity", default="all", choices=["all"] + list(BUILDERS.keys()))
    parser.add_argument("--consultant", default="Gabriel Cifuentes")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "reports" / "output"))
    args = parser.parse_args()

    bq_client = bigquery.Client(project=PROJECT_ID)
    client_info = queries.get_client_info(bq_client, args.client)
    if not client_info:
        print(f"No existe el cliente '{args.client}' en BigQuery.")
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    activities = list(BUILDERS.keys()) if args.activity == "all" else [args.activity]
    for activity in activities:
        output_path = output_dir / f"{args.client}_{activity}.pdf"
        result = BUILDERS[activity](
            bq_client, args.client, client_info["client_name"], args.consultant, output_path
        )
        if result:
            print(f"Generado: {result}")
        else:
            print(f"Sin datos para '{activity}' -- se omite.")


if __name__ == "__main__":
    main()
