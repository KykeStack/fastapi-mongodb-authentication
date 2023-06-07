from typing import Any, List, Union, Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from pymongo.collection import Collection
from pymongo.database import Database
from functionTypes.common import FunctionStatus
from schemas.msg import Msg
from schemas.token import AccessToken

from datetime import datetime, timedelta

from fastapi.security import OAuth2PasswordRequestForm

from api.deps import get_current_active_superuser, authenticate_user
from core import security

from dataBase.models.user import User, UpdateUser, CreateUser
from dataBase.client import session
from bson.objectid import ObjectId

router = APIRouter()
mssg = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )

def get_users_db() -> Union[Collection, Database]:
    try:
        collection = session['User']
        yield collection
    finally:
        session

def get_admin_db() -> Union[Collection, Database]:
    try:
        collection = session['Admin']
        yield collection
    finally:
        session


@router.get(
    "/all", 
    response_model=List[User],
    response_model_exclude_unset = True,
    response_description= "Get active users",
    response_model_exclude_none=True
)
def read_all_users(
    *,
    db: Collection = Depends(get_users_db),
    skip: int = 0,
    limit: int = 100,
    current_user: FunctionStatus = Depends(get_current_active_superuser),
) -> Any:
    """
    Retrieve all current users.
    """
    if not current_user.status:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    user_list = []
    users = db.find({'deleted': False}).limit(limit).skip(skip)
    for user in users:
        user.update({'id': str(user.get('_id'))})
        user_list.append(user)
    return user_list


@router.post(
    "/token", 
    response_model=AccessToken,
    response_description="Generate a new JWT token"    
)
async def signin_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    collection: Collection = Depends(get_admin_db)
):
    """
    Generate only a JWT access token 
    """
    valid_username = form_data.username.lower()
    user: FunctionStatus = authenticate_user(valid_username, form_data.password, admin=True)
    if not user.status:
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed; incorrect email or password"
            ) 
    id = user.content.get('_id')
    time= user.content.get('timeDelta')
    access_token = security.create_access_token(subject=id, admin=True, expires_delta=timedelta(minutes=time))
    try:
        data = collection.update_one(
            {"_id": id}, {"$set": {"accessToken": access_token, "updatedAt": datetime.now()}})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if not data.acknowledged:
        raise mssg
    responce = {"id" : str(id), "accessToken": access_token, "tokenType": "bearer"}
    return responce

@router.put(
    "/toggle-state",    
    response_model_exclude_unset = True,
    response_description= "toggle user state",
    response_model_exclude_none=True,
    response_model=Msg
)
def toggle_state(
    *,
    db: Collection = Depends(get_users_db),
    user_in: UpdateUser,
    current_user: FunctionStatus = Depends(get_current_active_superuser),
) -> Any:
    """
    Toggle user state (moderator function)
    """
    if not current_user.status:
        error_handler = FunctionStatus(
        functionName="toggle_state", status=False, section=0, message=current_user.message)
        print(error_handler)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    data = user_in.dict(exclude_none=True)
    id = data.get('id')
    data.pop('id')
    data.update({'updatedAt': datetime.now()})
    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data to update is required"
        ) 
    try:
        responce = db.update_one({"_id":  ObjectId(id)}, {"$set": data})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="toggle_state", status=False, section=2, message=error)
        print(error_handler)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error)
        ) 
    if not responce.acknowledged:
        raise mssg
    if responce.matched_count == 0:
        error_handler = FunctionStatus(
            functionName="toggle_state", status=False, section=2, message="No modify User")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        ) 
    if responce.modified_count == 0:
        error_handler = FunctionStatus(
            functionName="toggle_state", status=False, section=3, message="user is alredy up to date")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No modify data, user is alredy up to date"
        ) 
    return {"msg": "User state toggled successfully."}

@router.get("/tester", response_model=Msg)
def test_endpoint() -> Any:
    """
    Test current endpoint.
    """
    return {"msg": "Message returned ok."}
