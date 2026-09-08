"""
App de ingesta (drag & drop) para los CSV de evaluaciones de ciberseguridad.

Cubre lo que pide el caso para el modulo de importacion:
- Carga de archivos (drag & drop) para un cliente especifico.
- Previsualizacion antes de confirmar la carga.
- Indicadores de progreso / exito / error.
- Reimportar el mismo archivo reemplaza los datos anteriores (no duplica).
- Consulta de registros que no se pudieron importar, con el motivo.

Correr con:  streamlit run ingestion/app.py
"""

import os
import re
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from google.cloud import bigquery

PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", str(PROJECT_ROOT / "credentials" / "gcp-service-account.json"))

from ingestion.parsers import (  # noqa: E402
    domain_account_review,
    email_filter_check,
    eva_findings as eva_findings_parser,
    eva_top10_recommendations as eva_top10_parser,
    eva_vulnerability_aging as eva_aging_parser,
)
from ingestion import loader  # noqa: E402

PROJECT_ID = "prueba-gabriel-cifuentes-sisap"
DATASET_ID = "sisap_ciberseguridad"

ACTIVITY_LABELS = {
    "email_filter_check": "Email Filter Check",
    "domain_account_review": "Domain Account Review",
    "eva_findings": "Vulnerabilidades externas - Findings",
    "eva_aging": "Vulnerabilidades externas - Aging Analysis",
    "eva_top10": "Vulnerabilidades externas - Top 10 Recommendations",
}


@st.cache_resource
def get_client() -> bigquery.Client:
    return bigquery.Client(project=PROJECT_ID)


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "cliente"


def detect_source_kind(filename: str) -> str | None:
    name = filename.lower()
    if "email" in name and "filter" in name:
        return "email_filter_check"
    if "domain" in name and "account" in name:
        return "domain_account_review"
    if "top10" in name or "top-10" in name:
        return "eva_top10"
    if "aging" in name:
        return "eva_aging"
    if "findings" in name:
        return "eva_findings"
    return None


def save_upload_to_tempfile(uploaded_file) -> str:
    suffix = Path(uploaded_file.name).suffix or ".csv"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getvalue())
        return tmp.name


def list_clients(client: bigquery.Client) -> pd.DataFrame:
    query = f"SELECT client_id, client_name, vertical FROM `{PROJECT_ID}.{DATASET_ID}.clients` ORDER BY client_name"
    return client.query(query).result().to_dataframe()


def render_client_picker(client: bigquery.Client):
    st.subheader("1. Cliente")
    clients_df = list_clients(client)

    options = ["+ Nuevo cliente"] + [
        f"{row.client_name} ({row.client_id})" for row in clients_df.itertuples()
    ]
    choice = st.selectbox("Selecciona el cliente para esta carga", options)

    if choice == "+ Nuevo cliente":
        col1, col2 = st.columns(2)
        client_name = col1.text_input("Nombre del cliente", placeholder="Ej. Cliente Demo S.A.")
        vertical = col2.text_input("Vertical / industria (opcional)", placeholder="Ej. Retail")
        client_id = slugify(client_name) if client_name else None
        if client_name:
            st.caption(f"ID interno que se usara: `{client_id}`")
        return client_id, client_name, vertical
    else:
        idx = options.index(choice) - 1
        row = clients_df.iloc[idx]
        return row.client_id, row.client_name, row.vertical


def render_upload_and_load(client: bigquery.Client, client_id: str, client_name: str, vertical: str):
    st.subheader("2. Archivos CSV")
    consultant_name = st.text_input("Nombre del consultor", value="Gabriel Cifuentes")

    uploaded_files = st.file_uploader(
        "Arrastra aqui uno o varios CSV (o haz clic para seleccionarlos)",
        type=["csv"],
        accept_multiple_files=True,
    )
    if not uploaded_files:
        st.info("Sube al menos un archivo CSV para continuar.")
        return

    files_by_kind: dict[str, "st.runtime.uploaded_file_manager.UploadedFile"] = {}
    st.write("**Archivos detectados:**")
    for f in uploaded_files:
        kind = detect_source_kind(f.name)
        col1, col2 = st.columns([3, 2])
        col1.write(f.name)
        if kind:
            col2.success(ACTIVITY_LABELS[kind])
            files_by_kind[kind] = f
        else:
            manual_kind = col2.selectbox(
                "Tipo de archivo", ["(sin reconocer)"] + list(ACTIVITY_LABELS.keys()),
                format_func=lambda k: ACTIVITY_LABELS.get(k, k),
                key=f"kind_{f.name}",
            )
            if manual_kind != "(sin reconocer)":
                files_by_kind[manual_kind] = f

    if not files_by_kind:
        st.warning("No se pudo identificar el tipo de ninguno de los archivos subidos.")
        return

    parsed_cache = {}

    if "email_filter_check" in files_by_kind:
        _preview_email_filter_check(files_by_kind["email_filter_check"], parsed_cache)

    if "domain_account_review" in files_by_kind:
        _preview_domain_account_review(files_by_kind["domain_account_review"], parsed_cache)

    eva_kinds = {k: v for k, v in files_by_kind.items() if k in ("eva_findings", "eva_aging", "eva_top10")}
    if eva_kinds:
        _preview_eva(eva_kinds, parsed_cache)

    st.divider()
    if st.button("Confirmar carga a BigQuery", type="primary", disabled=not client_id):
        _run_load(client, client_id, client_name, vertical, consultant_name, parsed_cache)


def _preview_email_filter_check(uploaded_file, parsed_cache):
    st.markdown(f"**{ACTIVITY_LABELS['email_filter_check']}** -- `{uploaded_file.name}`")
    path = save_upload_to_tempfile(uploaded_file)
    parsed = email_filter_check.parse(path)
    parsed_cache["email_filter_check"] = (parsed, uploaded_file.name)

    col1, col2 = st.columns(2)
    col1.metric("Nivel de riesgo", parsed["summary"].get("risk_rating", "N/A"))
    col2.metric("Reduccion de riesgo estimada", f"${parsed['summary'].get('total_risk_reduction_usd', 0):,.0f}")
    with st.expander("Vista previa de recomendaciones"):
        st.dataframe(pd.DataFrame(parsed["recommendations"]))


def _preview_domain_account_review(uploaded_file, parsed_cache):
    st.markdown(f"**{ACTIVITY_LABELS['domain_account_review']}** -- `{uploaded_file.name}`")
    path = save_upload_to_tempfile(uploaded_file)
    parsed = domain_account_review.parse(path)
    parsed_cache["domain_account_review"] = (parsed, uploaded_file.name)

    col1, col2 = st.columns(2)
    col1.metric("Nivel de riesgo", parsed["summary"].get("risk_rating", "N/A"))
    col2.metric("Exposicion total", f"${parsed['summary'].get('total_exposure_usd', 0):,.0f}")
    with st.expander("Vista previa de recomendaciones"):
        st.dataframe(pd.DataFrame(parsed["recommendations"]))


def _preview_eva(eva_kinds, parsed_cache):
    st.markdown(f"**Evaluacion de Vulnerabilidades Externas**")
    findings = aging = top10 = None
    names = {}

    if "eva_findings" in eva_kinds:
        path = save_upload_to_tempfile(eva_kinds["eva_findings"])
        findings = eva_findings_parser.parse(path)
        names["findings"] = eva_kinds["eva_findings"].name
        st.write(f"Findings (`{names['findings']}`): {len(findings['findings'])} validos, {len(findings['rejected'])} rechazados")
        with st.expander("Vista previa - Findings"):
            st.dataframe(pd.DataFrame(findings["findings"]).head(20))
            if findings["rejected"]:
                st.warning("Filas rechazadas:")
                st.dataframe(pd.DataFrame(findings["rejected"]))

    if "eva_aging" in eva_kinds:
        path = save_upload_to_tempfile(eva_kinds["eva_aging"])
        aging = eva_aging_parser.parse(path)
        names["aging"] = eva_kinds["eva_aging"].name
        st.write(f"Aging Analysis (`{names['aging']}`): {len(aging['aging_rows'])} validos, {len(aging['rejected'])} rechazados")
        with st.expander("Vista previa - Aging Analysis"):
            st.dataframe(pd.DataFrame(aging["aging_rows"]).head(20))
            if aging["rejected"]:
                st.warning("Filas rechazadas:")
                st.dataframe(pd.DataFrame(aging["rejected"]))

    if "eva_top10" in eva_kinds:
        path = save_upload_to_tempfile(eva_kinds["eva_top10"])
        top10 = eva_top10_parser.parse(path)
        names["top10"] = eva_kinds["eva_top10"].name
        st.write(f"Top 10 Recommendations (`{names['top10']}`): {len(top10['recommendations'])} validos, {len(top10['rejected'])} rechazados")
        with st.expander("Vista previa - Top 10 Recommendations"):
            st.dataframe(pd.DataFrame(top10["recommendations"]))
            if top10["rejected"]:
                st.warning("Filas rechazadas:")
                st.dataframe(pd.DataFrame(top10["rejected"]))

    missing = [k for k in ("findings", "aging", "top10") if k not in names]
    if missing:
        st.info(f"Faltan por subir: {', '.join(missing)}. Puedes cargar solo lo que tengas disponible.")

    parsed_cache["eva"] = (findings, aging, top10, names)


def _run_load(client, client_id, client_name, vertical, consultant_name, parsed_cache):
    progress = st.progress(0, text="Iniciando carga...")
    steps = len(parsed_cache)
    done = 0
    results = []

    try:
        if "email_filter_check" in parsed_cache:
            parsed, filename = parsed_cache["email_filter_check"]
            progress.progress(done / steps, text=f"Cargando {filename}...")
            res = loader.load_email_filter_check(
                client, parsed, client_id, client_name, consultant_name, filename
            )
            results.append(("Email Filter Check", res))
            done += 1
            progress.progress(done / steps)

        if "domain_account_review" in parsed_cache:
            parsed, filename = parsed_cache["domain_account_review"]
            progress.progress(done / steps, text=f"Cargando {filename}...")
            res = loader.load_domain_account_review(
                client, parsed, client_id, client_name, consultant_name, filename
            )
            results.append(("Domain Account Review", res))
            done += 1
            progress.progress(done / steps)

        if "eva" in parsed_cache:
            findings, aging, top10, names = parsed_cache["eva"]
            progress.progress(done / steps, text="Cargando Evaluacion de Vulnerabilidades Externas...")

            findings_rows = findings["findings"] if findings else []
            aging_rows = aging["aging_rows"] if aging else []
            top10_rows = top10["recommendations"] if top10 else []
            report_date = findings_rows[0]["scan_date"] if findings_rows else None

            rejected_by_file = {}
            if findings:
                rejected_by_file[names["findings"]] = findings["rejected"]
            if aging:
                rejected_by_file[names["aging"]] = aging["rejected"]
            if top10:
                rejected_by_file[names["top10"]] = top10["rejected"]

            res = loader.load_external_vulnerability_assessment(
                client,
                findings=findings_rows, aging_rows=aging_rows, recommendations=top10_rows,
                client_id=client_id, client_name=client_name, consultant_name=consultant_name,
                findings_file=names.get("findings", "(no proporcionado)"),
                aging_file=names.get("aging", "(no proporcionado)"),
                recommendations_file=names.get("top10", "(no proporcionado)"),
                report_date=report_date,
                rejected_by_file=rejected_by_file,
            )
            results.append(("Evaluacion de Vulnerabilidades Externas", res))
            done += 1
            progress.progress(done / steps)

        progress.progress(1.0, text="Listo")
        st.success("Carga completada correctamente.")
        for label, res in results:
            st.write(f"- **{label}**: {res['rows_loaded']} filas cargadas"
                     + (f", {res['rows_rejected']} rechazadas" if res.get("rows_rejected") else ""))

    except Exception as exc:
        st.error(f"La carga fallo: {exc}")
        raise


def render_history(client: bigquery.Client):
    st.subheader("Historial de cargas")
    query = f"""
        SELECT started_at, client_id, activity_type, source_file, load_mode,
               rows_loaded, rows_rejected, status
        FROM `{PROJECT_ID}.{DATASET_ID}.load_batches`
        ORDER BY started_at DESC
        LIMIT 100
    """
    df = client.query(query).result().to_dataframe()
    st.dataframe(df, width='stretch')


def render_rejected(client: bigquery.Client):
    st.subheader("Registros con problemas de importacion")
    query = f"""
        SELECT rejected_at, client_id, source_file, row_number, validation_error, raw_row
        FROM `{PROJECT_ID}.{DATASET_ID}.rejected_rows`
        ORDER BY rejected_at DESC
        LIMIT 200
    """
    df = client.query(query).result().to_dataframe()
    st.dataframe(df, width='stretch')


def main():
    st.set_page_config(page_title="SISAP - Ingesta de Evaluaciones", layout="wide")
    st.title("Ingesta de Evaluaciones de Ciberseguridad")

    client = get_client()

    tab_carga, tab_historial, tab_rechazados = st.tabs(
        ["Cargar datos", "Historial de cargas", "Registros con problemas"]
    )

    with tab_carga:
        client_id, client_name, vertical = render_client_picker(client)
        st.divider()
        if client_id:
            render_upload_and_load(client, client_id, client_name, vertical)
        else:
            st.info("Escribe el nombre del cliente para continuar.")

    with tab_historial:
        render_history(client)

    with tab_rechazados:
        render_rejected(client)


if __name__ == "__main__":
    main()
