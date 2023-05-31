from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional

from datetime import datetime

from schemas.user import FullName

class CreateUser(BaseModel):
    username: str
    email: EmailStr
    password: Optional[str] = None 
    fullName: FullName
    birthdate: str
    gender: str
    country: str
    phoneNumber: Optional[str] = None
    userExperience: Optional[bool] = True
    updatedAt: datetime = datetime.now()
    createdAt: datetime = datetime.now()
    emailValidated: bool = False
    totpSecret: bool = False
    totpCounter: Optional[str] = None
    accessToken: Optional[str] = None
    refreshToken: Optional[str] = None
    disabled: bool = False
    deleted: bool = False
