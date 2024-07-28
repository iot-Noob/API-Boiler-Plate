from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from passlib.context import CryptContext
from fastapi.security import HTTPBearer
from App.RunQuery import RunQuery
import pyotp
import qrcode
from io import BytesIO
from App.GetEnvDate import key, algo, exptime,memcost,parallelism,hashlength,salt_length 
from typing import Dict, Union,List
from urllib.parse import urlparse, parse_qs
from fastapi import HTTPException, Query
from App.LoggingInit import *

 

# Set default values if the configuration values are None
default_memcost = 65536  # Example default value
default_parallelism = 2  # Example default value
default_hashlength = 32  # Example default value
default_salt_length = 16  # Example default value

pwd_context = PasswordHasher(
    memory_cost=int(memcost) if memcost is not None else default_memcost,
    parallelism=int(parallelism) if parallelism is not None else default_parallelism,
    hash_len=int(hashlength) if hashlength is not None else default_hashlength,
    salt_len=int(salt_length) if salt_length is not None else default_salt_length
    
)

oauth2_scheme = HTTPBearer()


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(hash=hashed_password, password=plain_password)
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password verification failed due to {e}")

    


async def get_password_hash(password):
    return pwd_context.hash(password=password)

async def get_user(username: str):
    try:
        user = await RunQuery(
            q=""" SELECT name,password,id,tfa_key FROM users WHERE name= ?""", val=(username,)
        )
        return user
    except Exception as e:
        raise HTTPException(404, f"User not found {e}")


async def authenticate_user(username: str, password: str):
    try:
        user = await get_user(username)

        if not user:
            return False
        if not await verify_password(password, user[1]):
            return False
        return user
    except Exception as e:
        return {"Error authenticaiton":e}


async def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        try:
            expire_minutes = int(exptime)  # Ensure exptime is an integer
        except ValueError:
            expire_minutes = (
                1320 
            )
        expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, key, algorithm=algo)
    return encoded_jwt


async def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, key, algorithms=[algo])

        return payload
    except JWTError as e:
        return None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = await decode_jwt(token.credentials)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format"
            )

        expiration_time = payload.get("exp")
        if expiration_time is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has no expiration time",
            )

        expiration_datetime = datetime.fromtimestamp(expiration_time, timezone.utc)
        if expiration_datetime <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
            )

        username: str = payload.get("sub")
        id: str = payload.get("user_id")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Username not found in token",
            )

        return {"username": username, "id": id}
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


async def authenticte_token(token):
    try:
        ueq = await RunQuery(
            q="""SELECT id, disabled FROM users WHERE id=?""", val=(token["id"],)
        )
       
        if not ueq:
            raise HTTPException(
                status_code=404, detail="Invalid token: user does not exist"
            )

        user_id, disabled = ueq[0], ueq[1]

        if disabled:
            raise HTTPException(
                status_code=403,
                detail="Account is disabled: cannot perform any action ask admin ",
            )

        return token

    except HTTPException as http_exc:
        raise http_exc
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token validation error: {e}")
 

async def get_user_role(token: str | None = None):
    return await RunQuery(
        q=""" SELECT user_role FROM users WHERE id = ?""", val=(token["id"],)
    )
 
 
 ### 2FA 
async def generate_secret():
    try:
        secret = pyotp.random_base32()
        return secret
    except Exception as e:
        return HTTPException(500,f"Canot generate secret due to {e}")

async def generate_qr_code(secret: str, app_name: str, company_name: str) -> Dict[str, Union[bytes, str]]:
    try:
        """Generate a QR code and return it as a dictionary with the QR code image bytes and provisioning URI."""
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=app_name, issuer_name=company_name)
        qr = qrcode.make(uri)
        
        buffer = BytesIO()
        qr.save(buffer, format='PNG')
        buffer.seek(0)
        
        return {"qr": buffer.getvalue(), "key": uri}
    except Exception as e:
        logging.error(f"Error generate QR due to {e}")
        return HTTPException(400,f"Error generate wr due to {e}")


async def qr_raw(txt):
    qr=qrcode.make(txt)
    buffer=BytesIO()
    qr.save(buffer,format="PNG")
    buffer.seek(0)
    return buffer.getvalue()
 

async def verify_2fa_code(secret, code):
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    except Exception as e:
        logging.error(f"Error create 2FA due to {e}")
        return HTTPException(400,f"fail to verify 2FA due to {e}")
async def extract_secret_from_uri(uri: str) -> str:
    try:
        """Extract the secret key from a TOTP provisioning URI."""
        parsed_uri = urlparse(uri)
        query_params = parse_qs(parsed_uri.query)
        secret = query_params.get('secret', [None])[0]
        return secret
    except Exception as e:
        logging.error(f"Error verify 2fa due to {e}")
        return HTTPException(400,f"Error canot extract secret key due to {e}")

