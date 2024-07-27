import os
from dotenv import load_dotenv,set_key
import base64

load_dotenv(override=True)
  
try:
    ef='./.env'
    dap = os.getenv("admin_paswd")
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
    ## AES 
    key=os.getenv("AES_KEY")
    ivs=os.getenv("AES_IV")
    ## Schegular
    sch_time=os.getenv("schedul_time")
except Exception as e:
    print(f"Error occur load env file in secutiry due to {e}")


def set_keys(key,value):
    try:
       
        set_key(ef, key,value)
    except Exception as e:
        print(f"Error set key due to {e}")
 
# print(f"memcost:::{memcost} pararellism:::{parallelism} hashlen::{hashlength} salt_len:::{salt_length}")

