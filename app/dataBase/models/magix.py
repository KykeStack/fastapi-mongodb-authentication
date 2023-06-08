from pydantic import BaseModel, EmailStr
from typing import Optional

from datetime import datetime
from bson.objectid import ObjectId as BsonObjectId

class PydanticObjectId(BsonObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, BsonObjectId):
            raise TypeError('ObjectId required')
        return v


class MagicData(BaseModel):
    foreignId: PydanticObjectId
    updatedAt: datetime = datetime.now()
    createdAt: datetime = datetime.now()
    claimToken: Optional[str] = None
    
    
class UpdateMagicData(BaseModel):
    updatedAt: datetime
    claimToken: Optional[str] = None
    
if __name__ == "__main__":
    ...