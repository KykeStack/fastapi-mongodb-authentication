from fastapi import APIRouter, HTTPException, status, Depends
from typing import Annotated, Union, Any
from datetime import datetime

from functionTypes.common import FunctionStatus
from schemas.msg import Msg
from bson.objectid import ObjectId

from dataBase.client import session
from pymongo.database import Database
from pymongo.collection import Collection

from api.deps import get_access_token

router = APIRouter()

mssg = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service Unavailable"
        )

def get_user_db() -> Union[Collection, Database]:
    try:
        collection = session['User']
        yield collection
    finally:
        session

@router.post("/", response_model=Msg)
def revoke_token(
    current_user: Annotated[FunctionStatus, Depends(get_access_token)],
    collection: Collection = Depends(get_user_db)
) -> Any:
    """
    Revoke a access token
    """
    if not current_user.status:
        if current_user.section == 1:
            raise mssg
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=current_user.message,
        )
    id = current_user.content.get('_id')
    try:
        data = collection.update_one(
            {"_id": id}, 
            {"$set": {"accessToken": "", "refreshToken": "", "updatedAt": datetime.now()}})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if not data.acknowledged:
        raise mssg
    return {"msg": "Token revoked"}

@router.get("/tester", response_model=Msg)
def test_endpoint() -> Any:
    """
    Test current endpoint.
    """
    return {"msg": "Message returned ok."}