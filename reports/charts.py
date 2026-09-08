"""Genera graficos como imagenes PNG en memoria (bytes) para insertar en los
informes PDF. Paleta simple y consistente entre graficos."""

import io
from typing import List, Optional, Sequence

import matplotlib
matplotlib.use("Agg")  # sin interfaz grafica, solo renderiza a archivo/bytes
import matplotlib.pyplot as plt

COLOR_PRIMARY = "#2C5F8A"
COLOR_CRITICAL = "#B23B3B"
COLOR_HIGH = "#D98032"
COLOR_MEDIUM = "#D9B23C"
COLOR_LOW = "#4C8C4A"
COLOR_NEUTRAL = "#8A8A8A"

SEVERITY_COLORS = {
    "Critical": COLOR_CRITICAL,
    "High": COLOR_HIGH,
    "Medium": COLOR_MEDIUM,
    "Low": COLOR_LOW,
}


def _fig_to_png_bytes(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def horizontal_bar_chart(labels: Sequence[str], values: Sequence[float], title: str,
                          value_format: str = "${:,.0f}", color: str = COLOR_PRIMARY) -> bytes:
    fig, ax = plt.subplots(figsize=(7, max(1.5, 0.5 * len(labels))))
    y_pos = range(len(labels))
    ax.barh(list(y_pos), values, color=color)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_title(title, fontsize=12, fontweight="bold")
    for i, v in enumerate(values):
        ax.text(v, i, " " + value_format.format(v), va="center", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _fig_to_png_bytes(fig)


def severity_bar_chart(severity_counts: dict, title: str = "Hallazgos por severidad") -> bytes:
    order = ["Critical", "High", "Medium", "Low"]
    labels = [s for s in order if s in severity_counts]
    values = [severity_counts[s] for s in labels]
    colors = [SEVERITY_COLORS.get(s, COLOR_NEUTRAL) for s in labels]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.bar(labels, values, color=colors)
    ax.set_title(title, fontsize=12, fontweight="bold")
    for i, v in enumerate(values):
        ax.text(i, v, str(v), ha="center", va="bottom", fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _fig_to_png_bytes(fig)


def trend_chart(x_labels: Sequence[str], values: Sequence[float], title: str,
                 value_format: str = "${:,.0f}") -> bytes:
    fig, ax = plt.subplots(figsize=(6.5, 3))
    ax.plot(x_labels, values, marker="o", color=COLOR_PRIMARY, linewidth=2)
    for i, v in enumerate(values):
        ax.annotate(value_format.format(v), (i, v), textcoords="offset points",
                     xytext=(0, 8), ha="center", fontsize=8)
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    ax.margins(y=0.25)
    fig.tight_layout()
    return _fig_to_png_bytes(fig)


def compliance_bar_chart(labels: Sequence[str], pct_values: Sequence[Optional[float]],
                          title: str = "Cumplimiento (%)") -> bytes:
    values = [v if v is not None else 0 for v in pct_values]
    colors = [COLOR_LOW if v >= 80 else COLOR_HIGH if v >= 40 else COLOR_CRITICAL for v in values]

    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar(labels, values, color=colors)
    ax.set_ylim(0, 100)
    ax.set_title(title, fontsize=12, fontweight="bold")
    for i, v in enumerate(values):
        ax.text(i, v, f"{v:.0f}%", ha="center", va="bottom", fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _fig_to_png_bytes(fig)
