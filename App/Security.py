from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from passlib.context import CryptContext
from fastapi.security import HTTPBearer
from App.RunQuery import RunQuery

from App.GetEnvDate import key, algo, exptime,memcost,parallelism,hashlength,salt_length 

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


async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(hash=hashed_password,password=plain_password)


async def get_password_hash(password):
    return pwd_context.hash(password=password)


async def get_user(username: str):
    try:
        user = await RunQuery(
            q=""" SELECT name,password,id FROM users WHERE name= ?""", val=(username,)
        )
        return user
    except Exception as e:
        raise HTTPException(404, f"User not found {e}")


async def authenticate_user(username: str, password: str):
    user = await get_user(username)

    if not user:
        return False
    if not await verify_password(password, user[1]):
        return False
    return user


async def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        try:
            expire_minutes = int(exptime)  # Ensure exptime is an integer
        except ValueError:
            expire_minutes = (
                15  # Default to 15 minutes if exptime is not a valid integer
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


 
