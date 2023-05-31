from typing import Generator, Union
from functionTypes.common import FunctionStatus

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError

from schemas.token import TokenPayload, MagicTokenPayload
from core.config import settings
from dataBase.client import session

from pymongo.database import Database
from bson.objectid import ObjectId

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

def get_db() -> Generator:
    try:
        collection = session['User']
        yield collection
    finally:
        session

def get_token_payload(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    return token_data


async def get_current_user(collection: Database = Depends(get_db), token: str = Depends(reusable_oauth2)) -> FunctionStatus:
    
    token_data = get_token_payload(token)
    print(token_data)
    if token_data.refresh or token_data.totp:
        # Refresh token is not a valid access token and TOTP True can only be used to validate TOTP
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    try:
        form_user: dict = collection.find_one(ObjectId(token_data.sub))
    except Exception as e:
        return FunctionStatus({"status": False, "section": 0, "message": f"Mongodb error: {e}"})
    finally:
        if form_user == None:
            raise HTTPException(status_code=404, detail="User not found")
        return FunctionStatus(status=True, content=form_user)
    


# def get_totp_user(collection: Database = Depends(get_db), token: str = Depends(reusable_oauth2)) -> FunctionReturn:
#     toke n_data = get_token_payload(token)
#     if token_data.refresh or not token_data.totp:
#         # Refresh token is not a valid access token and TOTP False cannot be used to validate TOTP
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Could not validate credentials",
#         )
#     try:
#         form_user: dict = collection.find_one(ObjectId(token_data.sub))
#     except Exception as e:
#         return FunctionStatus({"status": False, "section": 0, "message": f"Mongodb error: {e}"})
#     finally:
#         if form_user == None:
#             raise HTTPException(status_code=404, detail="User not found")
#         return {"status": True, "content" : form_user}
    

def get_magic_token(token: str = Depends(reusable_oauth2)) -> FunctionStatus:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        token_data = MagicTokenPayload(**payload)
    except (JWTError, ValidationError) as error:
        return FunctionStatus(status=False, section=0, message=f"JWTError, ValidationError: {error}")
    return FunctionStatus(status=True, content=token_data)


def get_refresh_user(collection = Depends(get_db), token: str = Depends(reusable_oauth2)) -> FunctionStatus:
    token_data = get_token_payload(token)
    if not token_data.refresh:
        return FunctionStatus(status=False, section=0, message="Could not validate credentials")
    try:
        form_user: dict = collection.find_one(ObjectId(token_data.sub))
    except Exception as e:
        return FunctionStatus(status=False, section=1, message=f"Mongodb error: {e}")
    if form_user == None or form_user.get('deleted'):
        return FunctionStatus(status=False, section=2, message="User not found")
    if form_user.get('disabled'):
        return FunctionStatus(status=False, section=3, message="Inactive user")
    return FunctionStatus(status=True, content=form_user)



    # Check and revoke this refresh token
    # token_obj = crud.token.get(token=token, user=user)
    # if not token_obj or not token_obj.is_valid:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Could not validate credentials",
    #     )
    # crud.token.cancel_refresh_token(db, db_obj=token_obj)
    # return user


# def get_current_active_user(
#     current_user: models.User = Depends(get_current_user),
# ) -> models.User:
#     if not crud.user.is_active(current_user):
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user


# def get_current_active_superuser(
#     current_user: models.User = Depends(get_current_user),
# ) -> models.User:
#     if not crud.user.is_superuser(current_user):
#         raise HTTPException(status_code=400, detail="The user doesn't have enough privileges")
#     return current_user


# def get_active_websocket_user(*, db: Session, token: str) -> models.User:
#     try:
#         payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGO])
#         token_data = schemas.TokenPayload(**payload)
#     except (jwt.JWTError, ValidationError):
#         raise ValidationError("Could not validate credentials")
#     if token_data.refresh:
#         # Refresh token is not a valid access token
#         raise ValidationError("Could not validate credentials")
#     user = crud.user.get(db, id=token_data.sub)
#     if not user:
#         raise ValidationError("User not found")
#     if not crud.user.is_active(user):
#         raise ValidationError("Inactive user")
#     return user
