"""
Carga resultados ya parseados hacia BigQuery.

Responsabilidades:
- Generar/registrar el 'assessment' (una corrida de una actividad para un
  cliente) en la tabla assessments.
- Insertar las tablas de detalle (summary, recommendations, findings...)
  ligadas a ese assessment_id.
- Si el mismo archivo se vuelve a importar para el mismo cliente, retira lo
  cargado antes de esa combinacion cliente+actividad+archivo (evita
  duplicados) antes de insertar de nuevo.
- Registrar cada carga en load_batches para trazabilidad.

Nota sobre el diseno: el proyecto usa el nivel gratuito ("sandbox") de
BigQuery, que NO permite sentencias DML (DELETE/UPDATE) sin tener
facturacion activada -- solo permite SELECT y "load jobs" (carga de
archivos/objetos). Por eso, en vez de un DELETE, la desduplicacion se hace
leyendo la tabla completa, filtrando en Python las filas que ya no aplican,
y reescribiendo la tabla (WRITE_TRUNCATE). A la escala de este proyecto de
practica esto es instantaneo; en un proyecto real con facturacion activada,
lo natural seria reemplazar esto por sentencias MERGE/DELETE.
"""

import datetime as dt
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from google.cloud import bigquery

PROJECT_ID = "prueba-gabriel-cifuentes-sisap"
DATASET_ID = "sisap_ciberseguridad"


def _table(name: str) -> str:
    return f"{PROJECT_ID}.{DATASET_ID}.{name}"


def _now():
    return datetime.now(timezone.utc)


def _json_safe(value: Any) -> Any:
    """Convierte fechas (date/datetime) a texto ISO para que el modulo json
    las pueda serializar; deja pasar el resto de tipos sin tocar."""
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    return value


def _load_json_rows(client: bigquery.Client, table_name: str, rows: List[Dict[str, Any]],
                     write_disposition: str = bigquery.WriteDisposition.WRITE_APPEND) -> None:
    """Inserta filas via 'load job' (carga por lotes), que si funciona en el
    nivel gratuito de BigQuery -- a diferencia de insert_rows_json (streaming
    insert) o de sentencias DML, que requieren tener facturacion activada."""
    rows = [_json_safe(row) for row in rows]
    schema = client.get_table(_table(table_name)).schema

    if not rows and write_disposition != bigquery.WriteDisposition.WRITE_TRUNCATE:
        return

    job_config = bigquery.LoadJobConfig(
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition=write_disposition,
        schema=schema,
    )
    job = client.load_table_from_json(rows, _table(table_name), job_config=job_config)
    job.result()  # espera a que el job termine; lanza excepcion si falla


def _read_all_rows(client: bigquery.Client, table_name: str) -> List[Dict[str, Any]]:
    return [dict(row) for row in client.query(f"SELECT * FROM `{_table(table_name)}`").result()]


def _rewrite_table_excluding(client: bigquery.Client, table_name: str, keep_predicate) -> None:
    """Reescribe la tabla dejando solo las filas para las que
    keep_predicate(fila) sea True. Reemplaza al DELETE (bloqueado en el
    nivel gratuito)."""
    existing = _read_all_rows(client, table_name)
    kept = [row for row in existing if keep_predicate(row)]
    _load_json_rows(client, table_name, kept, write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE)


def ensure_client(client: bigquery.Client, client_id: str, client_name: str, vertical: Optional[str] = None) -> None:
    """Crea el cliente en la tabla 'clients' si todavia no existe."""
    query = f"SELECT client_id FROM `{_table('clients')}` WHERE client_id = @client_id"
    job = client.query(
        query,
        job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("client_id", "STRING", client_id)]
        ),
    )
    if list(job.result()):
        return

    _load_json_rows(client, "clients", [{
        "client_id": client_id,
        "client_name": client_name,
        "vertical": vertical,
        "created_at": _now().isoformat(),
    }])


DETAIL_TABLES_BY_ACTIVITY = {
    "email_filter_check": ["email_filter_check_summary", "email_filter_check_recommendations"],
    "domain_account_review": ["domain_account_review_summary", "domain_account_review_recommendations"],
    "external_vulnerability_assessment": ["eva_findings", "eva_vulnerability_aging", "eva_top10_recommendations"],
}


def _remove_previous_load(client: bigquery.Client, client_id: str, activity_type: str, source_file: str) -> None:
    """Si este archivo ya se cargo antes para este cliente, retira sus datos
    (assessment + tablas de detalle) para evitar duplicados en la
    reimportacion, tal como pide el caso."""
    old_ids = {
        row["assessment_id"]
        for row in _read_all_rows(client, "assessments")
        if row["client_id"] == client_id and row["activity_type"] == activity_type and row["source_file"] == source_file
    }
    if not old_ids:
        return

    for table_name in DETAIL_TABLES_BY_ACTIVITY.get(activity_type, []):
        _rewrite_table_excluding(client, table_name, lambda row: row.get("assessment_id") not in old_ids)

    _rewrite_table_excluding(client, "assessments", lambda row: row.get("assessment_id") not in old_ids)


def _load_summary_recommendations_activity(
    client: bigquery.Client,
    parsed: Dict[str, Any],
    client_id: str,
    client_name: str,
    consultant_name: str,
    source_file: str,
    activity_type: str,
    summary_table: str,
    recommendations_table: str,
    extra_summary_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Carga generica para actividades con forma 'un resumen + N
    recomendaciones' (Email Filter Check y Domain Account Review)."""
    started_at = _now()
    batch_id = str(uuid.uuid4())

    ensure_client(client, client_id, client_name)
    _remove_previous_load(client, client_id, activity_type, source_file)

    assessment_id = str(uuid.uuid4())
    report_date = parsed["report_date"]

    assessment_row = {
        "assessment_id": assessment_id,
        "client_id": client_id,
        "activity_type": activity_type,
        "consultant_name": consultant_name,
        "profile_name": parsed["profile_name"],
        "report_date": report_date.isoformat() if report_date else None,
        "source_file": source_file,
        "load_batch_id": batch_id,
        "created_at": started_at.isoformat(),
    }
    _load_json_rows(client, "assessments", [assessment_row])

    summary_row = {"assessment_id": assessment_id, **parsed["summary"], **(extra_summary_fields or {})}
    _load_json_rows(client, summary_table, [summary_row])

    rec_rows = [
        {"assessment_id": assessment_id, **rec} for rec in parsed["recommendations"]
    ]
    _load_json_rows(client, recommendations_table, rec_rows)

    finished_at = _now()
    batch_row = {
        "batch_id": batch_id,
        "client_id": client_id,
        "activity_type": activity_type,
        "source_file": source_file,
        "load_mode": "overwrite",
        "rows_read": 1 + len(rec_rows),
        "rows_loaded": 1 + len(rec_rows),
        "rows_rejected": 0,
        "status": "success",
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
    }
    _load_json_rows(client, "load_batches", [batch_row])

    return {"assessment_id": assessment_id, "batch_id": batch_id, "rows_loaded": batch_row["rows_loaded"]}


def load_email_filter_check(
    client: bigquery.Client,
    parsed: Dict[str, Any],
    client_id: str,
    client_name: str,
    consultant_name: str,
    source_file: str,
) -> Dict[str, Any]:
    return _load_summary_recommendations_activity(
        client, parsed, client_id, client_name, consultant_name, source_file,
        activity_type="email_filter_check",
        summary_table="email_filter_check_summary",
        recommendations_table="email_filter_check_recommendations",
        extra_summary_fields={"domain": parsed.get("domain")},
    )


def load_domain_account_review(
    client: bigquery.Client,
    parsed: Dict[str, Any],
    client_id: str,
    client_name: str,
    consultant_name: str,
    source_file: str,
) -> Dict[str, Any]:
    return _load_summary_recommendations_activity(
        client, parsed, client_id, client_name, consultant_name, source_file,
        activity_type="domain_account_review",
        summary_table="domain_account_review_summary",
        recommendations_table="domain_account_review_recommendations",
    )
