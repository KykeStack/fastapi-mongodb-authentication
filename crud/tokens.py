from dataBase.models.magix import UpdateMagicData, MagicData
from functionTypes.common import FunctionStatus

from fastapi import HTTPException, status
from datetime import datetime
from typing import Optional

from pymongo.collection import Collection
from bson.objectid import ObjectId

NOT_FOUND_MESSAGE = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service Unavailable"
        )

def set_db_tokens(
    *, 
    collection: Collection, 
    token: str, 
    id: ObjectId,
    action_name: Optional[str] = None
):
    try:
        update_content = UpdateMagicData(claimToken=token, updatedAt=datetime.now())
        responce = collection.update_one({"foreignId": id}, {"$set": {**update_content.dict()}})
    except Exception as error:
        raise NOT_FOUND_MESSAGE
    
    if responce.modified_count == 0:
        new_content = MagicData(foreignId=id, claimToken=token)
        try:
            responce = collection.insert_one({**new_content.dict()})
        except Exception as error:
            raise NOT_FOUND_MESSAGE
        
    if not responce.acknowledged:
        raise NOT_FOUND_MESSAGE
    
def verify_token(
    *, 
    collection: Collection,  
    id: ObjectId,
    claim: str
):
    try: 
        db: dict = collection.find_one({"foreignId": id})
    except Exception as error:
        raise NOT_FOUND_MESSAGE
    
    if not db:
        raise NOT_FOUND_MESSAGE
    
    if db.get('claimToken') != claim:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token",
        )

if __name__ == "__main__":
    ...