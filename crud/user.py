from functionTypes.common import FunctionStatus
from pymongo.collection import Collection
from bson.objectid import ObjectId

from fastapi import HTTPException, status
from datetime import datetime
from typing import Union, Optional

NOT_FOUND_MESSAGE = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Operation Fail: Could not complete successfully")

def verify_email(
    *,
    collection: Collection,
    email: str,
    id: ObjectId
):
    mssg = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login failed; invalid claim.")
    try:
        found_user_email: dict = collection.find_one({"email": email})
    except Exception as error:
        raise mssg
    
    if not found_user_email:
        raise mssg
    
    if str(found_user_email.get('_id')) != str(id):
        raise mssg
    
def update_user(
    *,
    collection: Collection,
    id: ObjectId,
    data: dict,
    messge: Optional[str] = None,
    status_code: Optional[str] = None,
): 
    try:
        updated_at = datetime.now()
        data.update({"updatedAt": updated_at})
        responce = collection.update_one({"_id": id}, {"$set": data})
    except Exception as error:
        raise NOT_FOUND_MESSAGE
    
    if not responce.acknowledged:
        raise NOT_FOUND_MESSAGE
    
    if responce.matched_count == 0 or responce.modified_count == 0:
        raise NOT_FOUND_MESSAGE
        
    return updated_at

def delete_user(
    *,
    collection: Collection,
    id: ObjectId
):
    try:
        responce = collection.delete_one({"_id": id})
    except Exception as error:
        raise NOT_FOUND_MESSAGE
    
    if not responce.acknowledged:
        raise NOT_FOUND_MESSAGE
    
def find_one_document(
    *,
    collection: Collection, 
    query: Union[ObjectId, dict],
    return_value: Optional[bool] = None
) -> Union[dict, None] :
    try:
        responce = collection.find_one(query)
    except Exception as error:
        raise NOT_FOUND_MESSAGE
    
    if not responce and not return_value:
        raise NOT_FOUND_MESSAGE
    
    return responce

def unique_email_username(
    *, 
    collection: Collection, 
    email: str, 
    username: str
):
    try:
        found_documents = collection.find({
            "$or": [ {"email": email}, {"username": username}]}, {"username": 1, "email": 1 })
    except Exception as error:
        raise NOT_FOUND_MESSAGE
    
    if found_documents:
        for documents in found_documents:
            if (documents.get('email') == email
                ) or documents.get('username') == username:
                raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail= "username or email already exists"
                    )

if __name__ == "__main__":
    ...