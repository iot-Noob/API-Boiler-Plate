import os
from dotenv import load_dotenv

load_dotenv()

dap = os.getenv("admin_paswd")
 
try:
    key = os.getenv("SECRET_KEY")
    algo = os.getenv("ALGORITHM")
    exptime = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

except Exception as e:
    print(f"Error occur load env file in secutiry due to {e}")
log_path = os.getenv("log_filepath")


#load Argon2 config
memcost=os.getenv("memory_cost")
parallelism=os.getenv("parallelism")
hashlength=os.getenv("hash_len")
salt_length=os.getenv("salt_len")
