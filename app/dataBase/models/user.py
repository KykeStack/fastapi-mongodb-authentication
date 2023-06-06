from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional

from datetime import datetime
from bson.objectid import ObjectId as BsonObjectId

from schemas.user import FullName, Gender

class PydanticObjectId(BsonObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, BsonObjectId):
            raise TypeError('ObjectId required')
        return str(v)

class CreateUser(BaseModel):
    username: str
    email: EmailStr
    password: str
    fullName: FullName
    birthdate: str
    gender: Gender
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


class User(BaseModel):
    _id = PydanticObjectId
    id: str
    username: str
    email: EmailStr
    password: str
    fullName: FullName
    birthdate: str
    gender: str
    country: str
    phoneNumber: Optional[str] = None
    userExperience: bool
    updatedAt: datetime 
    createdAt: datetime 
    emailValidated: bool 
    totpSecret: bool 
    totpCounter: Optional[str] = None
    accessToken: Optional[str] = None
    refreshToken: Optional[str] = None
    disabled: bool
    deleted: bool

class UpdateUser(BaseModel):
    id: str
    emailValidated: Optional[bool] = None
    totpSecret: Optional[bool]= None
    totpCounter: Optional[str] = None
    disabled: Optional[bool]= None
    deleted: Optional[bool]= None
