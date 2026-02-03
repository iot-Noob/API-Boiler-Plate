from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from App.api.v1 import app_router
from contextlib import asynccontextmanager
from App.core.LoggingInit import get_core_logger

app = FastAPI(title="API Basic Boilerplate", version="0.0.1")
logger=get_core_logger(__name__)
 
@asynccontextmanager
async def lifespan():
    
    logger.info("App started")
    yield
    logger.info("app end")
# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to your specific needs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
 
app.include_router(app_router,prefix="/app/v1")
