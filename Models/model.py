from pydantic import BaseModel, EmailStr, validator, constr
import re

class User(BaseModel):
    name: str
    email: EmailStr
    password: str
    profile_pic: str = None
    disable: bool = False

    @validator("name")
    def name_must_be_non_empty(cls, v):
        if not v:
            raise ValueError("Name cannot be empty")
        return v

    @validator("email")
    def email_must_be_valid_format(cls, v):
        email_regex = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
        if not email_regex.match(v):
            raise ValueError("Invalid email format")
        return v

class UpdateUser(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    profile_pic: str | None = None
    disable: bool | None = None
    user_role: str | None = None
class TfaAuth(BaseModel):
    code: int

    @validator('code')
    def validate_code(cls, value):
        if not (100000 <= value <= 999999):
            raise ValueError('The code must be a 6-digit numeric value.')
        return value