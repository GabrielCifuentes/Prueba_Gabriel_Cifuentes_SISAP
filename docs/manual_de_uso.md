# Manual de Uso

## 1. Requisitos

- Python 3.11+ instalado.
- Un proyecto de Google Cloud con BigQuery habilitado.
- Una cuenta de servicio (service account) de ese proyecto con el rol
  "BigQuery Admin", con su llave descargada en formato JSON.

## 2. Instalacion

1. Clona el repositorio y entra a la carpeta del proyecto.
2. Instala las dependencias:
   ```
   pip install -r requirements.txt
   ```
3. Coloca el archivo JSON de la cuenta de servicio en
   `credentials/gcp-service-account.json` (esa carpeta esta excluida de git,
   nunca se sube).
4. Ajusta el `PROJECT_ID` en `bigquery/schema.py`,
   `bigquery/setup_dataset.py`, `ingestion/loader.py`, `ingestion/app.py` y
   `reports/queries.py` / `reports/generate_report.py` si vas a usar un
   proyecto de GCP distinto al de esta prueba.

## 3. Crear el dataset y las tablas en BigQuery

Solo se corre una vez (o cuando cambie el esquema en `bigquery/schema.py`):

```
python bigquery/setup_dataset.py
```

Es seguro correrlo varias veces: no borra ni sobreescribe tablas que ya
existan.

## 4. Cargar datos (app de ingesta)

```
streamlit run ingestion/app.py
```

Esto abre una pagina web (normalmente `http://localhost:8501`) con 3
pestañas:

- **Cargar datos**: selecciona o crea un cliente, sube uno o varios CSV
  (drag & drop) y confirma la carga.
  - La app reconoce automaticamente el tipo de archivo por su nombre. Si no
    lo reconoce, te deja elegirlo manualmente.
  - Los 3 archivos de vulnerabilidades externas (`EVA-CIS76-Findings...`,
    `EVA-Vulnerability-Aging...`, `EVA-Top10-Recommendations...`) se pueden
    subir juntos o por separado; si subes solo alguno, se carga solo lo
    disponible.
  - Antes de confirmar, se muestra una vista previa de los datos (KPIs,
    graficos, tablas) y cuantas filas se rechazaron por errores de
    validacion.
  - Si vuelves a subir el mismo archivo para el mismo cliente, reemplaza la
    carga anterior (no duplica datos).
- **Historial de cargas**: lista de todas las cargas realizadas (cliente,
  actividad, archivo, filas cargadas/rechazadas, exito/error).
- **Registros con problemas**: filas de CSV que no se pudieron importar,
  con el motivo especifico.

## 5. Ver los datos en Looker Studio (tableros)

1. Entra a [https://lookerstudio.google.com](https://lookerstudio.google.com).
2. Crea una fuente de datos nueva -> conector de **BigQuery**.
3. Selecciona el proyecto `prueba-gabriel-cifuentes-sisap` (o el que
   corresponda), el dataset `sisap_ciberseguridad`, y la tabla que quieras
   visualizar (por ejemplo `assessments` o cualquiera de las tablas de
   detalle).
4. Crea un informe nuevo con esa fuente y arma los graficos/filtros.

## 6. Generar los informes PDF

```
python reports/generate_report.py --client <client_id> --activity all
```

- `--client`: el `client_id` del cliente (lo puedes ver en la pestaña
  "Cargar datos" de la app, o consultando la tabla `clients`).
- `--activity`: `all` (los 3) o uno especifico: `email_filter_check`,
  `domain_account_review`, `external_vulnerability_assessment`.
- `--consultant`: nombre del consultor que aparece en la portada (por
  defecto "Gabriel Cifuentes").

Los PDF se guardan en `reports/output/`. Ejemplos ya generados estan en
`entregables/informes_pdf/`.

## 7. Estructura del repositorio

```
bigquery/          Esquema y creacion del dataset/tablas de BigQuery
ingestion/          Parsers, logica de carga y app de ingesta (Streamlit)
  parsers/          Un modulo por tipo de archivo CSV
  loader.py          Logica de carga a BigQuery (validacion, deduplicacion)
  app.py            App de ingesta (drag & drop)
reports/            Generador de informes PDF
  queries.py         Consultas a BigQuery
  charts.py          Graficos (matplotlib)
  generate_report.py Arma el PDF por actividad
Archivos_Ingesta/   CSV de muestra proporcionados para la prueba
entregables/        Informes PDF de ejemplo ya generados
docs/               Este manual y la documentacion tecnica
```
