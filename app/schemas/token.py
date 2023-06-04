from typing import Optional, Union
from pydantic import BaseModel, Field
from uuid import UUID

# class PydanticObjectId(ObjectId):
#     @classmethod
#     def __get_validators__(cls):
#         yield cls.validate

#     @classmethod
#     def validate(cls, v):
#         if not isinstance(v, ObjectId):
#             raise TypeError('ObjectId required')
#         return str(v)

class RefreshTokenBase(BaseModel):
    token: str
    is_valid: bool = True

class RefreshTokenCreate(RefreshTokenBase):
    pass

class RefreshTokenUpdate(RefreshTokenBase):
    is_valid: bool = Field(..., description="Deliberately disable a refresh token.")

class RefreshToken(RefreshTokenUpdate):
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    refresh: Optional[bool] = False
    totp: Optional[bool] = False


class MagicTokenPayload(BaseModel):
    sub: Optional[str] = None
    fingerprint: Optional[UUID] = None

class WebToken(BaseModel):
    claim: str
    
class AccessToken(BaseModel):
    id: str
    accessToken: str
    tokenType: str
    
class TokenData(BaseModel):
    userId: Optional[str] = None