from functionTypes.common import FunctionStatus
from pymongo.collection import Collection
from bson.objectid import ObjectId

from fastapi import HTTPException, status
from datetime import datetime
from typing import Union, Optional

test_mssg = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Operation Fail: Could not complete successfully")

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
        error_handler = FunctionStatus(
            functionName="verify_email", status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if found_user_email == None:
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
        error_handler = FunctionStatus(
            functionName="update_user", status=False, section=0, message=error)
        print(error_handler)
        raise test_mssg
    if not responce.acknowledged:
        error_handler = FunctionStatus(
            functionName="update_user", 
            status=False, 
            section=1,
            message=f"Error: acknowledged -> {responce.acknowledged}"
        )
        print(error_handler)
        raise test_mssg
    if responce.matched_count == 0:
        error_handler = FunctionStatus(
            functionName="update_user", status=False, section=2, message="No modify User")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    if responce.modified_count == 0:
        if messge:
            raise HTTPException(
                status_code=status_code,
                detail=messge
            )
        raise test_mssg
    return updated_at

def delete_user(
    *,
    collection: Collection,
    id: ObjectId
):
    try:
        responce = collection.delete_one({"_id": id})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="delete_user", status=False, section=3, message=error)
        print(error_handler)
        raise test_mssg
    if not responce.acknowledged:
        error_handler = FunctionStatus(
            functionName="update_user", status=False, section=3, 
            message=f"Error: acknowledged {responce.acknowledged}")
        print(error_handler)
        raise test_mssg
    
    
def find_one_document(
    *,
    collection: Collection, 
    query: Union[ObjectId, dict],
    return_value: Optional[bool] = None
) -> Union[dict, None] :
    try:
        responce = collection.find_one(query)
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="find_one_document", status=False, section=0, message=error)
        print(error_handler)
        raise test_mssg
    if responce == None and not return_value:
        raise test_mssg
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
        error_handler = FunctionStatus(
            functionName="unique_email_username", status=False, section=0, message=error)
        print(error_handler)
        raise test_mssg
    if found_documents != None:
        for documents in found_documents:
            if documents.get('email') == email:
                match = "email already exists"
            if documents.get('username') == username:
                match = "username already exists"
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=match
                )

if __name__ == "__main__":
    ...