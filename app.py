from __future__ import annotations

import hashlib
import logging
import io

import plotly.graph_objects as go
import streamlit as st

from phishtrace.parser import parse_email
from phishtrace.classifier import classify_email
from phishtrace.scoring import score_email
from phishtrace.geo import lookup_ip
from phishtrace.report import build_report_data, report_to_html, report_to_json

LOGGER = logging.getLogger(__name__)
st.set_page_config(page_title="PhishTrace AI", layout="wide")


def verdict_color(verdict: str) -> str:
    return {"Low": "#166534", "Suspicious": "#b45309", "High": "#b91c1c"}[verdict]


def hop_map(geo_results: list) -> go.Figure:
    resolved = [result for result in geo_results if result.resolved
                and result.latitude is not None and result.longitude is not None]
    figure = go.Figure()
    if not resolved:
        return figure
    for index, result in enumerate(resolved, 1):
        figure.add_trace(go.Scattergeo(
            lon=[result.longitude], lat=[result.latitude],
            text=f"Hop {result.ip}<br>{result.ip}<br>{result.city}, {result.country}",
            hoverinfo="text",
            marker={"size": 12, "color": "#2563eb"},
            name=f"Hop {index}",
        ))
    figure.add_trace(go.Scattergeo(
        lon=[result.longitude for result in resolved],
        lat=[result.latitude for result in resolved],
        mode="lines",
        line={"width": 2, "color": "#94a3b8"},
        hoverinfo="skip",
    ))
    figure.update_layout(
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        height=430,
        geo={"projection_type": "natural earth", "showland": True,
             "landcolor": "#f8fafc", "showocean": True, "oceancolor": "#eef2f7"},
    )
    return figure


st.title("PhishTrace AI")
uploaded = st.sidebar.file_uploader("Upload .eml file", type=["eml"])
st.sidebar.markdown("### Model status")
st.sidebar.write("Checked during analysis")
st.sidebar.markdown("### Geolocation status")
st.sidebar.write("ipwho.is lookup enabled")

if uploaded is None:
    st.info("Upload an .eml file to begin analysis.")
    st.stop()

file_bytes = uploaded.getvalue()
if not file_bytes:
    st.error("The uploaded file is empty.")
    st.stop()

try:
    email = parse_email(file_bytes)
except Exception as exc:
    LOGGER.exception("Unexpected parser failure")
    st.error(f"Could not analyze this file ({type(exc).__name__}).")
    st.stop()

classification = classify_email(email)
score, verdict, findings, ai_unavailable = score_email(email, classification)
geo_results = []
for hop in email.hops:
    if hop.ip:
        geo_results.append(lookup_ip(hop.ip, hop.timestamp or ""))

st.sidebar.markdown("### Model status")
if classification.status == "available":
    st.sidebar.success("Model available")
else:
    st.sidebar.warning("AI stage unavailable")
st.sidebar.markdown("### Geolocation status")
resolved_count = sum(result.resolved for result in geo_results)
st.sidebar.write(f"{resolved_count} public hop(s) resolved")

if ai_unavailable:
    st.warning("AI stage unavailable; the displayed score was renormalized using available findings.")

top = st.columns([1, 3])
with top[0]:
    gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "/100"},
        gauge={"axis": {"range": [0, 100]},
               "bar": {"color": verdict_color(verdict)},
               "steps": [{"range": [0, 29], "color": "#dcfce7"},
                         {"range": [30, 59], "color": "#fef3c7"},
                         {"range": [60, 100], "color": "#fee2e2"}]},
    ))
    gauge.update_layout(height=220, margin={"l": 20, "r": 20, "t": 20, "b": 20})
    st.plotly_chart(gauge, use_container_width=True)
with top[1]:
    st.markdown(f"<h2 style='color:{verdict_color(verdict)}'>{verdict} verdict</h2>",
                unsafe_allow_html=True)
    st.write(build_report_data(uploaded.name, file_bytes, email, classification,
                               score, verdict, findings, geo_results,
                               ai_unavailable)["summary"]["reasoning"])

findings_tab, headers_tab, body_tab, map_tab, report_tab = st.tabs(
    ["Findings", "Headers and Hops", "Body Analysis", "Trace Map", "Admin Report"]
)
with findings_tab:
    if not findings:
        st.info("No findings were triggered.")
    for finding in findings:
        st.markdown(f"**{finding.category.title()} - {finding.points} points**")
        st.write(finding.evidence)
with headers_tab:
    st.subheader("Headers")
    st.json(email.raw_headers)
    st.subheader("Hops")
    if email.hops:
        st.dataframe([{
            "Hop": hop.index, "From": hop.from_host, "By": hop.by_host,
            "IP": hop.ip or "", "Timestamp": hop.timestamp or ""
        } for hop in email.hops], use_container_width=True)
    else:
        st.info("No Received headers were available.")
with body_tab:
    st.subheader("Model result")
    if classification.status == "available":
        st.write(f"Probability: {classification.probability:.1%}")
        st.write(f"Model: {classification.model_name}")
    else:
        st.warning(classification.reason)
    st.subheader("Rule-based body signals")
    if classification.body_signals:
        for signal in classification.body_signals:
            st.write(f"- {signal.evidence} ({signal.points} points)")
    else:
        st.info("No rule-based body signals were detected.")
with map_tab:
    if resolved_count == 0:
        st.info("No resolved public hop locations are available.")
    else:
        st.plotly_chart(hop_map(geo_results), use_container_width=True)
with report_tab:
    report = build_report_data(uploaded.name, file_bytes, email, classification,
                               score, verdict, findings, geo_results,
                               ai_unavailable)
    st.subheader("Admin report")
    st.json(report)
    html_report = report_to_html(report)
    json_report = report_to_json(report)
    st.download_button("Download HTML report", html_report,
                       file_name="phishtrace-admin-report.html", mime="text/html")
    st.download_button("Download JSON report", json_report,
                       file_name="phishtrace-admin-report.json", mime="application/json")
