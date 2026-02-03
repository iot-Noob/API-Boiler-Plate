from fastapi import APIRouter
from .UserAuth import router

app_router=APIRouter()
app_router.include_router(router,prefix="/auth")