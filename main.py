"""
OwlEyeEngine - Vercel & ASGI Production Serverless Entrypoint (v4.0 Enterprise)

This module re-exports the FastAPI `app` with Kernel Telemetry, Prometheus Exporter,
and Active Defense APIs so platforms like Vercel, Railway, Render, or Docker can
detect and serve it directly.
"""
import os

# Force demo mode on serverless platforms if not explicitly configured
os.environ.setdefault("OWLEYE_DEMO_MODE", "true")

from web_dashboard import app, DEMO_MODE  # noqa: E402

# ASGI Contract
handler = app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", os.getenv("OWLEYE_PORT", "8000")))
    uvicorn.run(app, host="0.0.0.0", port=port)
