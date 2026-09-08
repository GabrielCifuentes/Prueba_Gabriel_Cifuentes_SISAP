"""
Crea (si no existen) el dataset y las tablas definidas en schema.py.
Es seguro correrlo varias veces: no borra ni sobreescribe tablas existentes.

Uso:
    GOOGLE_APPLICATION_CREDENTIALS=./credentials/gcp-service-account.json \
    python bigquery/setup_dataset.py
"""

import os
import sys

from google.cloud import bigquery
from google.api_core.exceptions import NotFound

sys.path.insert(0, os.path.dirname(__file__))
from schema import TABLES  # noqa: E402

PROJECT_ID = "prueba-gabriel-cifuentes-sisap"
DATASET_ID = "sisap_ciberseguridad"
LOCATION = "US"


def get_client() -> bigquery.Client:
    return bigquery.Client(project=PROJECT_ID)


def ensure_dataset(client: bigquery.Client) -> None:
    dataset_ref = bigquery.DatasetReference(PROJECT_ID, DATASET_ID)
    try:
        client.get_dataset(dataset_ref)
        print(f"Dataset '{DATASET_ID}' ya existe.")
    except NotFound:
        dataset = bigquery.Dataset(dataset_ref)
        dataset.location = LOCATION
        dataset.description = (
            "Datos de evaluaciones de ciberseguridad (email filter check, "
            "domain account review, evaluacion de vulnerabilidades externas) "
            "para multiples clientes/verticales/anios."
        )
        client.create_dataset(dataset)
        print(f"Dataset '{DATASET_ID}' creado en {LOCATION}.")


def ensure_tables(client: bigquery.Client) -> None:
    for table_name, cfg in TABLES.items():
        table_ref = bigquery.DatasetReference(PROJECT_ID, DATASET_ID).table(table_name)
        try:
            client.get_table(table_ref)
            print(f"  - Tabla '{table_name}' ya existe.")
            continue
        except NotFound:
            pass

        table = bigquery.Table(table_ref, schema=cfg["schema"])

        if "time_partitioning" in cfg:
            table.time_partitioning = bigquery.TimePartitioning(**cfg["time_partitioning"])
        if "clustering_fields" in cfg:
            table.clustering_fields = cfg["clustering_fields"]

        client.create_table(table)
        print(f"  - Tabla '{table_name}' creada.")


def main() -> None:
    client = get_client()
    print(f"Conectado al proyecto: {client.project}")
    ensure_dataset(client)
    ensure_tables(client)
    print("Listo.")


if __name__ == "__main__":
    main()
