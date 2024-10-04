from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from Route.MainRoutes import Route

app = FastAPI(title="API Basic Boilerplate", version="0.0.1")

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to your specific needs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# # Event handler to create table on startup
# @app.on_event("startup")
# async def startup_event():
#     await create_table_user()
 
#     print("TABLE CREATE SUCESS!!!")


# Include routes
app.include_router(Route)
