"""Consultas a BigQuery que alimentan los informes PDF."""

from typing import Any, Dict, List, Optional

from google.cloud import bigquery

PROJECT_ID = "prueba-gabriel-cifuentes-sisap"
DATASET_ID = "sisap_ciberseguridad"


def _t(name: str) -> str:
    return f"`{PROJECT_ID}.{DATASET_ID}.{name}`"


def get_client_info(client: bigquery.Client, client_id: str) -> Optional[Dict[str, Any]]:
    query = f"SELECT * FROM {_t('clients')} WHERE client_id = @client_id"
    job = client.query(query, job_config=bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("client_id", "STRING", client_id)]
    ))
    rows = list(job.result())
    return dict(rows[0]) if rows else None


def get_assessment_history(client: bigquery.Client, client_id: str, activity_type: str) -> List[Dict[str, Any]]:
    """Todas las evaluaciones de esta actividad para el cliente, de mas
    antigua a mas reciente (para comparativos entre periodos)."""
    query = f"""
        SELECT * FROM {_t('assessments')}
        WHERE client_id = @client_id AND activity_type = @activity_type
        ORDER BY report_date ASC, created_at ASC
    """
    job = client.query(query, job_config=bigquery.QueryJobConfig(query_parameters=[
        bigquery.ScalarQueryParameter("client_id", "STRING", client_id),
        bigquery.ScalarQueryParameter("activity_type", "STRING", activity_type),
    ]))
    return [dict(r) for r in job.result()]


def get_latest_assessment(client: bigquery.Client, client_id: str, activity_type: str) -> Optional[Dict[str, Any]]:
    history = get_assessment_history(client, client_id, activity_type)
    return history[-1] if history else None


def get_rows(client: bigquery.Client, table_name: str, assessment_id: str, order_by: Optional[str] = None) -> List[Dict[str, Any]]:
    order_clause = f"ORDER BY {order_by}" if order_by else ""
    query = f"SELECT * FROM {_t(table_name)} WHERE assessment_id = @assessment_id {order_clause}"
    job = client.query(query, job_config=bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("assessment_id", "STRING", assessment_id)]
    ))
    return [dict(r) for r in job.result()]


def get_row(client: bigquery.Client, table_name: str, assessment_id: str) -> Optional[Dict[str, Any]]:
    rows = get_rows(client, table_name, assessment_id)
    return rows[0] if rows else None
