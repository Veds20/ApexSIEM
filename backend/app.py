from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import threading
import logging

from backend.database import engine, Base
from backend.routes import router
from backend.services.log_ingestion import start_log_watcher
from backend.auth import create_default_admin

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AI SOC Console - Real Log Ingestion Mode")
    create_default_admin()
    thread = threading.Thread(target=start_log_watcher, daemon=True)
    thread.start()
    logger.info("Real log watcher started.")
    yield
    logger.info("AI SOC Console shutting down.")

app = FastAPI(title="AI SOC Console", version="3.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
