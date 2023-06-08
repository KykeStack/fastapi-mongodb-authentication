from dataBase.models.magix import UpdateMagicData, MagicData
from functionTypes.common import FunctionStatus

from fastapi import HTTPException, status
from datetime import datetime
from typing import Optional

from pymongo.collection import Collection
from bson.objectid import ObjectId

mssg = HTTPException(
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
        error_handler = FunctionStatus(
            functionName='set_db_tokens', status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if responce.modified_count == 0:
        new_content = MagicData(foreignId=id, claimToken=token)
        try:
            responce = collection.insert_one({**new_content.dict()})
        except Exception as error:
            error_handler = FunctionStatus(
                functionName='set_db_tokens', status=False, section=1, message=error)
            print(error_handler)
            raise mssg
    if not responce.acknowledged:
        error_handler = FunctionStatus(
            functionName='set_db_tokens', status=False, section=2, 
            message=f"Error: acknowledged -> {responce.acknowledged}")
        print(error_handler)
        raise mssg
    
def verify_token(
    *, 
    collection: Collection,  
    id: ObjectId,
    claim: str
):
    try: 
        db: dict = collection.find_one({"foreignId": id})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="validate_magic_link", status=False, section=2, message=error)
        print(error_handler)
        raise mssg
    if db == None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )  
    if db.get('claimToken') != claim:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Token",
        )
if __name__ == "__main__":
    ...