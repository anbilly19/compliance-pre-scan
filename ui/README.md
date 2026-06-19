# Compliance Pre-Scan — Streamlit UI

## Prerequisites

The FastAPI backend must be running before starting the UI.

## Start backend

```powershell
uv run uvicorn compliance_scan.api.app:app --reload
```

## Start UI (separate terminal)

```powershell
uv pip install streamlit requests pandas
streamlit run ui/app.py
```

Or set a custom backend URL:

```powershell
$env:BACKEND_URL = "http://localhost:8000"
streamlit run ui/app.py
```

## Pages

| Page | Description |
|---|---|
| 📤 Upload & Scan | Upload a file, see risk level, decision banner, and per-hit details |
| 📋 Audit Trail | Browse and filter all compliance events with colour-coded risk levels |
| 📥 Betriebsrat Export | Generate and download a date-filtered CSV for works council / audit |
