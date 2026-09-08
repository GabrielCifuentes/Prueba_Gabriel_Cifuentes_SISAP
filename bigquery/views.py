"""
Vistas (VIEW) de BigQuery pensadas para consumo directo desde Looker Studio.

Las tablas base (email_filter_check_summary, eva_findings, etc.) solo
tienen assessment_id -- para poder filtrar por cliente, fecha o consultor
directamente en un grafico de Looker Studio (sin tener que "combinar
datos" manualmente), estas vistas ya traen esos campos unidos desde
'assessments' y 'clients'.

Crear una vista es una operacion de metadatos (DDL), no mueve ni
copia datos, y esta permitida en el nivel gratuito de BigQuery.
"""

import os
import sys
from pathlib import Path

from google.cloud import bigquery

PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", str(PROJECT_ROOT / "credentials" / "gcp-service-account.json"))

PROJECT_ID = "prueba-gabriel-cifuentes-sisap"
DATASET_ID = "sisap_ciberseguridad"
DS = f"{PROJECT_ID}.{DATASET_ID}"

VIEWS = {
    "vw_assessments": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, c.vertical,
            a.activity_type, a.consultant_name, a.profile_name,
            a.report_date, a.source_file, a.created_at
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
    """,
    "vw_email_filter_check": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, a.profile_name, s.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.email_filter_check_summary` s USING (assessment_id)
        WHERE a.activity_type = 'email_filter_check'
    """,
    "vw_email_filter_check_recommendations": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, r.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.email_filter_check_recommendations` r USING (assessment_id)
        WHERE a.activity_type = 'email_filter_check'
    """,
    "vw_domain_account_review": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, a.profile_name, s.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.domain_account_review_summary` s USING (assessment_id)
        WHERE a.activity_type = 'domain_account_review'
    """,
    "vw_domain_account_review_recommendations": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, r.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.domain_account_review_recommendations` r USING (assessment_id)
        WHERE a.activity_type = 'domain_account_review'
    """,
    "vw_eva_findings": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, f.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.eva_findings` f USING (assessment_id)
        WHERE a.activity_type = 'external_vulnerability_assessment'
    """,
    "vw_eva_vulnerability_aging": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, g.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.eva_vulnerability_aging` g USING (assessment_id)
        WHERE a.activity_type = 'external_vulnerability_assessment'
    """,
    "vw_eva_top10_recommendations": f"""
        SELECT
            a.assessment_id, a.client_id, c.client_name, a.consultant_name,
            a.report_date, r.* EXCEPT (assessment_id)
        FROM `{DS}.assessments` a
        JOIN `{DS}.clients` c USING (client_id)
        JOIN `{DS}.eva_top10_recommendations` r USING (assessment_id)
        WHERE a.activity_type = 'external_vulnerability_assessment'
    """,
}


def main():
    client = bigquery.Client(project=PROJECT_ID)
    for view_name, query in VIEWS.items():
        view_ref = f"{DS}.{view_name}"
        view = bigquery.Table(view_ref)
        view.view_query = query.strip()
        client.delete_table(view_ref, not_found_ok=True)
        client.create_table(view)
        print(f"Vista creada: {view_name}")


if __name__ == "__main__":
    sys.exit(main())
