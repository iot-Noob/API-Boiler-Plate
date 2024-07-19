
from pydantic import BaseModel, EmailStr, validator
from fastapi import HTTPException
import sqlite3
import re
import os
from App.GetEnvDate import db_path,db_name

class User(BaseModel):
    name: str
    email: EmailStr
    password: str
    profile_pic: str = None
    disable: bool = False

    @validator("name")
    def name_must_be_unique(cls, v):
        
        if db_name and db_path:
            if not os.path.exists(ffp):
                os.makedirs(db_path,exist_ok=True)
            ffp=os.path.join(db_path,db_name)
            con = sqlite3.connect(ffp)

        elif db_name:
            con = sqlite3.connect(str(db_name))
        elif not db_path and not db_name or not db_name or not db_path:
            con = sqlite3.connect("databases.db")
        else:
            return HTTPException(400,"No db path define for sqlite")
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE name = ?", (v,))
        if cur.fetchone()[0] > 0:
            con.close()
            raise ValueError("Username already exists")
        con.close()
        return v

    @validator("email")
    def email_must_be_unique_and_valid_format(cls, v):
        # Check email format
        email_regex = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
        if not email_regex.match(v):
            raise ValueError("Invalid email format")

        # Check email uniqueness
        con = sqlite3.connect("vid_conv_data.db")
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE email = ?", (v,))
        if cur.fetchone()[0] > 0:
            con.close()
            raise ValueError("Email already exists")
        con.close()
        return v


class UpdateUser(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    profile_pic: str | None = None
    disable: bool | None = None
    user_role: str | None = None
