import os
from dotenv import load_dotenv

load_dotenv(override=True)

dap = os.getenv("admin_paswd")
 
try:
    key = os.getenv("SECRET_KEY")
    algo = os.getenv("ALGORITHM")
    exptime = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
    log_path = os.getenv("log_filepath")
    
    #load Argon2 config
    memcost=os.getenv("memory_costs")
    parallelism=os.getenv("pararellisms")
    hashlength=os.getenv("hash_length")
    salt_length=os.getenv("salt_length")
    db_path=os.getenv("database_paths")
    db_name=os.getenv("database_names")
    ## 2FA data
    company_name=os.getenv("comp_names")
    app_name=os.getenv("app_names")
except Exception as e:
    print(f"Error occur load env file in secutiry due to {e}")





# print(f"memcost:::{memcost} pararellism:::{parallelism} hashlen::{hashlength} salt_len:::{salt_length}")

