# Documentacion Tecnica

## 1. Arquitectura general

```
CSV (consultores)  -->  Parsers (Python)  -->  Loader (Python)  -->  BigQuery
                                                                       |
                                                                       +--> Looker Studio (tableros)
                                                                       +--> Generador de informes (PDF)
```

- **Ingesta**: app en Streamlit (`ingestion/app.py`) para cargar CSV con
  drag & drop, validarlos y subirlos a BigQuery.
- **Repositorio de datos**: BigQuery, proyecto `prueba-gabriel-cifuentes-sisap`,
  dataset `sisap_ciberseguridad`.
- **Visualizacion**: Looker Studio conectado directo a BigQuery.
- **Informes**: script Python (`reports/generate_report.py`) que arma un PDF
  por actividad a partir de lo que ya esta en BigQuery.

El stack es Python de punta a punta (parsers, carga, app web, generacion de
PDF), lo que permite reutilizar el mismo codigo de validacion/transformacion
en todos los puntos del flujo.

## 2. Modelo de datos (BigQuery)

Dataset: `sisap_ciberseguridad`. Todas las tablas usan `assessment_id` como
llave para relacionar el detalle de una evaluacion con su ficha general.

### Tablas dimension / control

| Tabla | Proposito |
|---|---|
| `clients` | Un renglon por cliente (id, nombre, vertical/industria). Permite multiples clientes y verticales. |
| `assessments` | Un renglon por "corrida" de una actividad para un cliente: liga `client_id`, `activity_type`, `consultant_name`, `report_date`, `source_file`. Es el punto de union entre todas las tablas de detalle. |
| `load_batches` | Auditoria de cada carga: cuantas filas se leyeron/cargaron/rechazaron, modo (overwrite), estado. |
| `rejected_rows` | Filas de CSV que no pasaron validacion, con el motivo especifico (ver seccion 4). |

### Tablas de hecho (una por actividad)

| Actividad | Tablas |
|---|---|
| Email Filter Check | `email_filter_check_summary`, `email_filter_check_recommendations` |
| Domain Account Review | `domain_account_review_summary`, `domain_account_review_recommendations` |
| Evaluacion de Vulnerabilidades Externas | `eva_findings`, `eva_vulnerability_aging`, `eva_top10_recommendations` |

`activity_type` en `assessments` toma los valores `email_filter_check`,
`domain_account_review` o `external_vulnerability_assessment`. Para esta
ultima actividad, los 3 archivos CSV que la componen (findings, aging
analysis, top10 recommendations) se cargan bajo un mismo `assessment_id`,
porque conceptualmente son una sola evaluacion.

El esquema completo (campos y tipos) esta definido en un solo lugar:
`bigquery/schema.py`. Se crea/actualiza corriendo `bigquery/setup_dataset.py`.

## 3. Por que dos formatos distintos de CSV

- `Email-filter-check-*.csv` y `domain-account-review-report.csv` son
  reportes exportados como filas `Seccion/Item/Detalle/Valor` (formato
  llave-valor, no tabular). Se interpretan con un parser dedicado
  (`ingestion/parsers/email_filter_check.py`,
  `ingestion/parsers/domain_account_review.py`) que reconoce cada
  Seccion/Item conocido y arma un resumen + lista de recomendaciones.
- Los 3 CSV de `EVA-*` si son tablas normales (una fila por hallazgo o
  recomendacion), y se parsean directamente
  (`ingestion/parsers/eva_findings.py`,
  `eva_vulnerability_aging.py`, `eva_top10_recommendations.py`).

## 4. Validacion de datos

- **Encoding**: cada parser intenta abrir el archivo como `utf-8-sig` y, si
  falla, como `latin-1` (encodings tipicos de exports de herramientas de
  seguridad en Windows).
- **Filas invalidas** (solo aplica a los 3 CSV tabulares de EVA, donde cada
  fila es un registro independiente): se descarta una fila y se registra el
  motivo cuando falta un campo obligatorio (`Host_IP`, `Vulnerability_Name`,
  `Rank`, `Recommendation`) o cuando una fecha no se puede interpretar. Esas
  filas se guardan en `rejected_rows` (columna `raw_row` con el contenido
  original en JSON, y `validation_error` con el motivo), y se puede consultar
  desde la pestaña "Registros con problemas" de la app.
- Los CSV de tipo reporte (Email Filter Check, Domain Account Review) no se
  validan fila por fila porque no son tabulares: se interpretan como un solo
  documento estructurado.

## 5. Reimportar un archivo sin duplicar

Si se vuelve a cargar el mismo archivo para el mismo cliente, el loader
localiza el `assessment_id` anterior (mismo `client_id` + `activity_type` +
`source_file`) y retira sus datos antes de insertar los nuevos.

**Detalle importante**: el proyecto usa el nivel gratuito ("sandbox") de
BigQuery, que no permite sentencias DML (`DELETE`/`UPDATE`) sin tener
facturacion activada. Por eso, en vez de `DELETE`, la funcion
`_rewrite_table_excluding` en `ingestion/loader.py` lee la tabla completa,
filtra en Python las filas que ya no aplican, y reescribe la tabla
(`WRITE_TRUNCATE`). A la escala de este proyecto esto es instantaneo; en un
proyecto real con facturacion activada, lo natural seria reemplazar esto por
sentencias `MERGE`/`DELETE`.

## 6. Limitaciones conocidas del nivel gratuito de BigQuery (decisiones documentadas)

Durante el desarrollo se encontraron 3 restricciones del modo sandbox de
BigQuery (sin facturacion), documentadas aqui porque explican decisiones de
diseno que de otra forma no serian obvias:

1. **Sin streaming inserts** (`insert_rows_json`): el proyecto usa
   `load_table_from_json` (carga por lotes / "load job") en su lugar, que si
   esta permitido sin facturacion. El caso de estudio menciona
   explicitamente esta disyuntiva (`insert_rows_json` vs
   `load_table_from_file`); aqui se opto por la segunda por esta razon.
2. **Sin DML** (`DELETE`/`UPDATE`): ver seccion 5.
3. **Expiracion automatica a 60 dias**: tanto el dataset como cada tabla
   quedan con una expiracion maxima de 60 dias que **no se puede quitar ni
   aumentar sin activar facturacion** (se intento explicitamente y la API
   rechaza el cambio con el mensaje *"Table expiration time must be less
   than 60 days while in sandbox mode"*). Ademas, si se particiona una tabla
   por fecha, cada particion hereda esa misma expiracion **calculada desde
   la fecha de la particion, no desde la fecha de carga** -- por lo que al
   cargar datos con fechas de hace mas de 60 dias (como los datos
   trimestrales historicos de este caso) BigQuery los borraba
   silenciosamente segundos despues de cargarlos. Por eso el esquema final
   **no particiona ninguna tabla por fecha** (solo usa *clustering*, que no
   expira datos); a esta escala de datos particionar no aportaba beneficio
   de rendimiento de todas formas. Se dejo asi (en vez de activar
   facturacion) porque la presentacion de este caso ocurre dentro de la
   ventana de 60 dias.

## 7. Uso de Inteligencia Artificial

Se utilizo Claude Code (Anthropic) como asistente de desarrollo durante todo
el proyecto, de forma interactiva y supervisada:

- **Diseno del esquema de BigQuery**: propuesta inicial de tablas a partir
  del analisis de los 5 CSV de muestra, revisada y ajustada por mi
  (por ejemplo, se le pidio agregar el campo de reduccion total de riesgo en
  dolares que el caso pedia explicitamente y que faltaba en la primera
  version).
- **Escritura de los parsers y el loader**: los parsers se escribieron
  iterativamente, probando cada uno contra el CSV real y revisando la salida
  antes de conectarlo a BigQuery.
- **Diagnostico de las restricciones del sandbox de BigQuery** (seccion 6):
  los 3 errores (streaming insert, DML, expiracion a 60 dias) se
  encontraron corriendo el codigo contra el proyecto real, no de forma
  teorica; el asistente investigo cada mensaje de error de la API y propuso
  la solucion (cambiar a load jobs, reescribir en vez de borrar, quitar el
  particionado).
- **App de carga (Streamlit) y generador de informes (reportlab +
  matplotlib)**: escritos por el asistente a partir de los requisitos del
  caso, probados corriendo la app real y generando los PDF contra los datos
  ya cargados en BigQuery (no se acepto el codigo sin antes ver el
  resultado real).

En resumen: la IA se uso para acelerar la escritura de codigo repetitivo
(parsers similares, tablas de reportes) y para diagnosticar errores de una
API que no conocia de antemano (limitaciones del sandbox de BigQuery), pero
cada decision de diseno (estructura de tablas, que validar, como manejar
duplicados) fue revisada y aprobada por mi antes de aplicarse.

## 8. Como generar los tableros e informes

- **Looker Studio**: se conecta directo como fuente de datos de BigQuery al
  dataset `sisap_ciberseguridad` (ver manual de uso). Looker Studio es
  unicamente una herramienta de visualizacion: aunque tiene un conector de
  "subir archivo", ese archivo queda almacenado dentro de Looker Studio como
  fuente aislada y **no se inserta en BigQuery ni en ninguna base de datos**.
  Por eso la carga de datos (validacion, deduplicacion, error-handling) vive
  en la app de Streamlit, y Looker Studio solo lee lo que ya esta en
  BigQuery -- son responsabilidades separadas a proposito, como en cualquier
  arquitectura BI real.
- **Informes PDF**: `python reports/generate_report.py --client <client_id>
  --activity all`. Genera un PDF por actividad en `reports/output/`.

## 9. Seguridad de la app de ingesta y trabajo futuro

La app de carga (`ingestion/app.py`) es adecuada para esta prueba/demo, pero
tiene limitaciones conocidas si se quisiera usar en produccion con datos
reales de clientes:

**Lo que ya mitiga riesgos:**
- Las credenciales de la cuenta de servicio nunca se versionan (excluidas
  via `.gitignore`).
- Todas las consultas parametrizadas (`bigquery.ScalarQueryParameter` /
  `ArrayQueryParameter`), sin concatenar texto de usuario en SQL -> sin
  riesgo de inyeccion SQL.
- El contenido de los CSV solo se lee como datos (`csv.DictReader`), nunca
  se ejecuta.
- La app corre solo en localhost, no esta expuesta a internet.

**Lo que falta para un entorno de produccion real:**
- **Sin autenticacion**: cualquiera que abra la app puede cargar datos de
  cualquier cliente; no hay control de acceso por consultor/cliente.
- **Permisos de la cuenta de servicio demasiado amplios** ("BigQuery
  Admin"); en produccion deberia acotarse a `BigQuery Data Editor` +
  `BigQuery Job User`.
- **Sin cifrado en transito** si se expusiera mas alla de localhost (habria
  que servirla detras de HTTPS).

**Alternativas gestionadas de Google/Microsoft para este mismo problema**
(subir un archivo -> validarlo -> cargarlo a una base de datos), si se
quisiera evitar mantener la app a mano:

- **Cloud Run + Identity-Aware Proxy (IAP)** (Google): desplegar esta misma
  app de Streamlit en Cloud Run, con IAP exigiendo login de Google antes de
  dejar entrar a nadie. Es la opcion que mas conserva la logica de
  validacion ya construida, solo le agrega autenticacion real sin escribir
  codigo de login.
- **AppSheet** (Google, incluido en Workspace): permite armar una app de
  carga de datos con login de Google y permisos por usuario "sin codigo",
  conectada a BigQuery. Mas rapido de configurar que programar una app,
  pero menos flexible para la logica de validacion especifica de cada CSV
  que ya tenemos (parsers por tipo de reporte, deteccion de encoding, etc.).
- **Cloud Storage + Cloud Function/Cloud Run activada por evento**: los
  consultores suben el CSV a una carpeta de Cloud Storage (con permisos de
  Google Cloud IAM controlando quien puede subir), y una funcion se dispara
  automaticamente para validarlo y cargarlo a BigQuery. Mas "serverless" y
  con auditoria nativa (Cloud Audit Logs), pero sin interfaz de
  previsualizacion como la que pide el caso.
- **Herramientas de Microsoft** (Power Automate, Power BI dataflows):
  tecnicamente podrian recibir el archivo (por ejemplo desde SharePoint) y
  moverlo a alguna base de datos, pero como todo este proyecto esta
  construido sobre BigQuery (no sobre Azure/SQL Server), mezclar
  herramientas de Microsoft aqui agregaria complejidad entre nubes sin
  ningun beneficio real -- no se recomienda para este caso.

Para el alcance de esta prueba se opto por la app de Streamlit hecha a la
medida (en vez de una de estas alternativas) porque el caso explicitamente
evalua "el control del desarrollador" sobre la logica de ingesta y
validacion, algo que una herramienta low-code como AppSheet abstraeria.
