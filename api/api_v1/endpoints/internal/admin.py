from typing import Any, List, Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from pymongo.collection import Collection
from functionTypes.common import FunctionStatus
from schemas.msg import Msg
from schemas.token import AccessToken

from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from core import security

from api.deps import get_current_active_superuser, authenticate_user, get_user_db, get_admin_db
from crud.user import update_user

from dataBase.models.user import User, UpdateUser
from bson.objectid import ObjectId

router = APIRouter()
mssg = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )

@router.get(
    "/all", 
    response_model=List[User],
    response_model_exclude_unset = True,
    response_description= "Get active users",
    response_model_exclude_none=True
)
def read_all_users(
    *,
    db: Collection = Depends(get_user_db),
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
    users = db.find({}).limit(limit).skip(skip)
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
    time = user.content.get('timeDelta')
    access_token = security.create_access_token(subject=id, admin=True, expires_delta=timedelta(minutes=time))
    data = {"accessToken": access_token}
    update_user(collection=collection, id=id, data=data)
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
    db: Collection = Depends(get_user_db),
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
    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data to update is required"
        )
    id = data.get('id')
    data.pop('id')
    update_user(
        collection=db, 
        id=ObjectId(id), 
        data=data, 
        messge="user is alredy up to date", 
        status_code=status.HTTP_400_BAD_REQUEST
    ) 
    return {"msg": "User state toggled successfully."}

if __name__ == "__main__":
    ...
