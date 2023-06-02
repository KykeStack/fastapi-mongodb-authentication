from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional

from datetime import datetime

class CreateUser(BaseModel):
    foreignId: str
    email: EmailStr
    updatedAt: datetime = datetime.now()
    createdAt: datetime = datetime.now()
    claimToken: Optional[str] = None