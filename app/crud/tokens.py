from dataBase.models.magix import UpdateMagicData, MagicData
from functionTypes.common import FunctionStatus

from fastapi import HTTPException, status
from datetime import datetime

from pymongo.collection import Collection
from bson.objectid import ObjectId

mssg = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service Unavailable"
        )

async def set_db_tokens(
    *, 
    collection: Collection, 
    token: str, 
    id: ObjectId
):
    try:
        update_content = UpdateMagicData(claimToken=token, updatedAt=datetime.now())
        responce = collection.update_one({"foreignId": id}, {"$set": {**update_content.dict()}})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName='set_db_tokens', status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if not responce.acknowledged:
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
            raise mssg