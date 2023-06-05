
from schemas.user import UserOut, UpdateUserData
from schemas.token import AccessToken
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm

from functionTypes.common import FunctionStatus
from modules.ValidateData import validate_data

from typing import Annotated
from bson.objectid import ObjectId
from datetime import datetime

from dataBase.client import session

from core import security
from api.deps import get_current_active_user, authenticate_user

router = APIRouter()
collection = session['User']
mssg = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )

@router.get(
    "/users/me", 
    response_model=UserOut,  
    response_model_exclude_unset = True,
    response_description= "Get user data if not disabled",
    response_model_exclude_none=True
)
async def get_current_user(
    current_user: Annotated[FunctionStatus, Depends(get_current_active_user)]):
    """
    Get user data if not disabled
    """
    if not current_user.status:
        if current_user.section == 0:
            user_message: FunctionStatus = current_user.message
            if (
                (user_message.section == 2)
                or (user_message.section == 3)
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Invalid JWT token",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            if (
                (user_message.section == 1)
                or (user_message.section == 0)
            ):
                raise mssg
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail='User is inactive',
                headers={"WWW-Authenticate": "Bearer"}
            )
    return current_user.content


@router.post(
    "/token", 
    response_model=AccessToken,
    response_description="Generate a new JWT token"    
)
async def signin_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Generate only a JWT access token 
    """
    valid_username = form_data.username.lower()
    user: FunctionStatus = authenticate_user(valid_username, form_data.password)
    if not user.status:
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed; incorrect email or password"
            ) 
    id = str(user.content.get('_id'))
    access_token = security.create_access_token(subject=id)
    try:
        data = collection.update_one({"_id": ObjectId(id)}, {"$set": {"accessToken": access_token}})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if not data.acknowledged:
        raise mssg
    responce = { "id" : id, "accessToken": access_token, "tokenType": "bearer" }
    return responce


@router.put(
    "/users/me", 
    response_description= "Update the current user data",
    response_model=UserOut,
    response_model_exclude_none=True
)
async def update_current_user(
    form: UpdateUserData,
    current_user_valid: Annotated[FunctionStatus, Depends(get_current_active_user)]
): 
    """
    Update the current user data
    """
    if not current_user_valid.status:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )  
    current_user: dict = current_user_valid.content
    valid_data = form.dict(exclude_none=True)
    if not valid_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data to update is required"
        )  
    if form.email != None:
        try:
            find_email = collection.find_one({'email': form.email})
        except Exception as error:
            error_handler = FunctionStatus(
                functionName="update_current_user", status=False, section=0, message=error)
            print(error_handler)
            raise mssg
        if find_email is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already exists"
                )
    if form.username != None:
        try:
            find_username = collection.find_one({"username": form.username})
        except Exception as error:
            error_handler = FunctionStatus(
                functionName="update_current_user", status=False, section=1, message=error)
            print(error_handler)
            raise mssg
        print(find_username)
        if find_username is not None:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username already exists"
                )  
    data = validate_data(current_user, valid_data)
    if not data.status:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=data.message
        )
    time: datetime = datetime.now()     
    user = data.content
    user.update({'updatedAt' : time})
    try:
        responce = collection.update_one(
            {"_id": current_user.get("_id")},
                {"$set": user}
                )
        if responce.raw_result.get('nModified') != 1:
            raise mssg
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="update_current_user", status=False, section=2, message=error)
        raise mssg 
    valid_data.update(
        {'id': str(current_user.get('_id')),
        'createdAt': current_user.get('createdAt'),
        'updatedAt' : time}
        )
    return valid_data
        
if __name__ == "__main__":
    ...
