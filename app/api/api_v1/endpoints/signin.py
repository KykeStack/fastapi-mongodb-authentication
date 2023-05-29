from core.security import (
    get_current_active_user, 
    authenticate_user, 
    create_access_token, 
    verify_password, 
    get_password_hash, 
    __cached__
)
    
from schemas.user import UserIn, UserOut, Token, UpdateUserData

from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from typing import Annotated
from datetime import datetime
from dataBase.client import session


collection = session['User']

router = APIRouter()

"""
Get user data if not disabled
"""
@router.get(
    "/users/me", 
    response_model=UserOut,  
    response_model_exclude_unset = True,
    response_description= "Get user data if not disabled",
    response_model_exclude_none=True
)
async def get_current_user(
    current_user: Annotated[UserIn, Depends(get_current_active_user)]
    ):
    user: dict = current_user
    if not user.get('status'):
        mssg: dict = user.get('message')
        if mssg.get('section') == 1:
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=mssg.get('message'),
            headers={"WWW-Authenticate": "Bearer"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User is disabled",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user.get('content')

"""
Generate a new JWT token
"""
@router.post(
    "/token", 
    response_model=Token,
    response_description="Generate a new JWT token"    
)
async def signin_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    valid_username = form_data.username.lower()
    user = authenticate_user(valid_username, form_data.password)
    if not user.get('status'):
        print(f"{user.get('section')}, {user.get('message')}")
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"}
            ) 
    id = str(user.get('content').get('_id'))
    access_token = create_access_token(subject=id)
    responce = { "id" : id, "accessToken": access_token, "tokenType": "bearer" }
    return responce

"""
Update the current user data
"""
@router.put(
    "/users/me", 
    response_description= "Update the current user data",
    response_model=UserOut,
    response_model_exclude_none=True
)
async def update_current_user(
    form:  UpdateUserData,
    current_user_valid: Annotated[UserIn, Depends(get_current_active_user)]
):  
    mssg = HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service Unavailable"
            )
    if not current_user_valid.get('status'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid User or JWT expire "
        )  
    current_user: dict = current_user_valid.get('content') 
    valid_data = form.dict(exclude_none=True)
    if not valid_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data to update is required"
        )  
    if form.privacyPolicy == False:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "The privacy policy is not accepted"
        ) 
    if form.email != None:
        try:
            find_email = collection.find_one({'email': form.email})
        except Exception as err:
            print(
            {"status": False,
                "section": 0, 
                "message": err})
            raise mssg
        if find_email is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already exists"
                )
    if form.username != None:
        try:
            find_username = collection.find_one({"username": form.username})
        except Exception as err:
            print(
            {"status": False,
                "section": 1, 
                "message": err})
            raise mssg
        if find_username is not None:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username already exists"
                )
    plain_password = valid_data.get("password", None)
    
    if plain_password != None:
        verified_password = verify_password(
            plain_password=plain_password, 
            hashed_password=current_user.get("password")
        )
        if verified_password.get('content'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password"
            )
        hash_password = get_password_hash(form.password)
        if not hash_password.get('status'):
            raise mssg
        valid_data.update({"password": hash_password.get('content')})
        
    valid_data.pop("privacyPolicy", None)
    load_data = {}
    for keys, values in valid_data.items():
        dict_to_compare = current_user.get(keys)
        if dict_to_compare == values:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Current value: {dict_to_compare} in key {keys}, is equal to new value: {values}"
            )
        if str(type(values)) == "<class 'dict'>" or str(type(keys)) == "<class 'list'>":
            for nested_key, nested_value in values.items():
                other_dict = current_user.get(keys).get(nested_key)
                if str(nested_value) == str(other_dict):
                    mssg = f"Current value: {other_dict} -> {nested_key}, is equal to new value: {nested_value}"
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=mssg
                    )
                load_data[f"{keys}.{nested_key}"] = nested_value
        else: load_data[keys] = values
        
    time: datetime = datetime.now()
    load_data.update({'updatedAt' : time}) 
    data = collection.update_one (
        {"_id": current_user.get("_id")}, {
            "$set": load_data})
    
    if data.raw_result.get('nModified') != 1:
        raise mssg
    
    valid_data.update(
        {'id': str(current_user.get('_id')), 'createdAt': current_user.get('createdAt'),'updatedAt' : time})
    
    return valid_data
        
if __name__ == "__main__":
    ...
