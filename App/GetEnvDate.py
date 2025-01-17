import os
from dotenv import load_dotenv

load_dotenv(override=True)

dap = os.getenv("admin_paswd")
 
try:
    key = os.getenv("SECRET_KEY")
    algo = os.getenv("ALGORITHM")
    exptime = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

except Exception as e:
    print(f"Error occur load env file in secutiry due to {e}")
log_path = os.getenv("log_filepath")
 
db_path=os.getenv("database_path")
db_name=os.getenv("database_name")
 