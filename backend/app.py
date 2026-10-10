from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import threading
import logging
import os
import json

from backend.routes import router as main_router
from backend.routes.incidents import router as incidents_router
from backend.routes.soar import router as soar_router
from backend.services.log_ingestion import start_log_watcher
from backend.auth import create_default_admin, decode_token
from backend.config import get_settings
from backend.database import SessionLocal
from backend.models import User
from backend.services.websocket_manager import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ApexSIEM starting in configured log-ingestion mode")
    settings.validate_required()
    create_default_admin()
    thread = threading.Thread(target=start_log_watcher, daemon=True)
    thread.start()
    logger.info("Log watcher thread started.")
    yield
    logger.info("ApexSIEM shutting down.")


app = FastAPI(
    title="ApexSIEM",
    version="3.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(main_router)
app.include_router(incidents_router)
app.include_router(soar_router)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Browser WebSocket APIs cannot set Authorization headers, so accept the
    # bearer token as a query parameter. Clients must avoid logging this URL.
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if not username:
            await websocket.close(code=1008)
            return

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user is None:
                await websocket.close(code=1008)
                return
        finally:
            db.close()
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await manager.send_personal_message({"type": "pong"}, websocket)
            except json.JSONDecodeError:
                continue
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "dist"))
ASSETS_DIR = os.path.join(FRONTEND_DIST, "assets")

if os.path.exists(ASSETS_DIR):
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    index_file = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Frontend build not found. Run npm run build inside frontend folder."}
