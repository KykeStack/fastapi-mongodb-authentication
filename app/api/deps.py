from typing import Union, Annotated, Optional
from functionTypes.common import FunctionStatus

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError, parse_obj_as

from schemas.token import TokenPayload, MagicTokenPayload
from functionTypes.common import FunctionStatus

from core.config import settings
from dataBase.client import session

from pymongo.database import Database
from bson.objectid import ObjectId
from pymongo.collection import Collection
from pymongo.database import Database

from schemas.token import TokenData
from passlib.context import CryptContext

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")  

def get_db() -> Union[Collection, Database]:
    try:
        collection = session['User']
        yield collection
    finally:
        session

def verify_password(*, plain_password: str, hashed_password: str) -> FunctionStatus:
    try:
        is_valid_password = pwd_context.verify(plain_password, hashed_password)
    except Exception as error:
        print(error)
        return FunctionStatus(status=False, section=0, message=f"CryptContext error: {error}")
    if not is_valid_password:
        return FunctionStatus(status=False, section=1, message="Invalid user password")
    return FunctionStatus(status=True, content=is_valid_password)

def get_password_hash(password: str) -> FunctionStatus:
    try:
        unhash_password = pwd_context.hash(password)
    except Exception as error:
        return FunctionStatus(status=False, section=0, message=f"CryptContext error: {error}")
    return FunctionStatus(status=True, content=unhash_password)

def authenticate_user(current_user: str, password: str, admin: Optional[bool] = False) -> FunctionStatus:
    if admin:
        collection = session['Admin']
    else:
        collection = session.User
    try:
        form_user: dict = collection.find_one({'email': current_user})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName='authenticate_user', status=False, section=0, message=f"Mongodb error: {error}")
        print(error_handler)
        print(form_user)
        return error_handler
    if form_user == None:
        error_handler = FunctionStatus(
            functionName='authenticate_user', status=False, section=1, message=f"User not found in database")
        print(error_handler)
        return error_handler
    if form_user.get('deleted'):
        error_handler = FunctionStatus(
            functionName='authenticate_user', status=False, section=2, message=f"User not found in database")
        print(error_handler)
        return error_handler
    unhash_password: FunctionStatus = verify_password(
        plain_password=password, hashed_password=form_user.get("password"))
    if not unhash_password.status:
        error_handler = FunctionStatus(
            functionName='authenticate_user', status=False, section=3, message="Invalid user password")
        print(error_handler)
        return error_handler
    return FunctionStatus(status=True, content=form_user)

def get_user(by_id: str, admin: Optional[bool] = False) -> FunctionStatus:
    if not admin:
        collection = session.User
    else: 
        collection = session['Admin']
    try:
        user: dict = collection.find_one(ObjectId(by_id)) 
    except Exception as error:
        error_handler = FunctionStatus(
            functionName='get_user', status=False, section=0, message= f"Mongodb error: {error}")
        print(error_handler)
        return error_handler
    if user == None:
        error_handler = FunctionStatus(
            functionName='get_user', status=False, section=1, message=f"User not found in database")
        print(error_handler)
        return error_handler
    user.update({'id': str(user.get('_id'))})
    return FunctionStatus(status=True, content=user)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> FunctionStatus:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: dict = payload.get("sub")
        if user_id == None:
            error_handler = FunctionStatus(
                functionName='get_current_user', status=False, section=0, message=f"Afther jwt.decode found Security Issues")
            print(error_handler)
            return error_handler
        token_data = TokenData(userId=user_id)
        print(payload)
        from_get_user: FunctionStatus = get_user(by_id=token_data.userId, admin=payload.get('admin'))
        if not from_get_user.status:
            error_handler = FunctionStatus(
                functionName='get_current_user', status=False, section=1, message=from_get_user)
            print(error_handler)
            return error_handler
        user = from_get_user.content
        print(user.get('accessToken'))
        print(token)
        if user.get('accessToken') != token:
            error_handler = FunctionStatus(
                functionName='get_current_user', status=False, section=2, message=f"JWT Token is deprecated")
            print(error_handler)
            return error_handler
    except JWTError as error:
        return FunctionStatus(status=False, section=3, message=f"JWTError: {error}")
    return FunctionStatus(status=True, content=user)

async def get_current_active_user(current_user: Annotated[FunctionStatus, Depends(get_current_user)]) -> FunctionStatus:
    if not current_user.status:
        return FunctionStatus(
            functionName='get_current_active_user', status=False, section=0, message=current_user)
    user: dict = current_user.content
    if user.get('disabled'):
        return FunctionStatus(
            functionName='get_current_active_user', status=False, section=1, message=f"Invalid User")
    if user.get('deleted'):
        return FunctionStatus(
            functionName='get_current_active_user', status=False, section=2, message=f"User not found")
    return  FunctionStatus(status=True, content=user)


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


def get_magic_token(token: str = Depends(reusable_oauth2)) -> FunctionStatus:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        token_data = MagicTokenPayload(**payload)
    except (JWTError, ValidationError) as error:
        return FunctionStatus(status=False, section=0, message=f"JWTError, ValidationError: {error}")

    return FunctionStatus(status=True, content=token_data)


def get_refresh_user(token: str = Depends(reusable_oauth2)) -> FunctionStatus:
    collection = session.User
    token_data = get_token_payload(token)
    if not token_data.refresh:
        return FunctionStatus(status=False, section=0, message="Could not validate credentials")
    try:
        form_user: dict = collection.find_one(ObjectId(token_data.sub))
    except Exception as e:
        return FunctionStatus(status=False, section=1, message=f"Mongodb error: {e}")
    if form_user == None or form_user.get('deleted'):
        return FunctionStatus(status=False, section=3, message="User not found")
    if token != form_user.get('refreshToken'):
        return FunctionStatus(status=False, section=2, message="Could not validate credentials")
    if form_user.get('disabled'):
        return FunctionStatus(status=False, section=4, message="Inactive user")
    if form_user.get('deleted'):
        return FunctionStatus(status=False, section=5, message="Could not validate credentials")
    return FunctionStatus(status=True, content=form_user)

def get_access_token(token: str = Depends(reusable_oauth2)) -> FunctionStatus:
    collection: Collection = session.User
    token_data = get_token_payload(token)
    if token_data.refresh:
        return FunctionStatus(
            functionName="get_access_token", status=False, section=0, message="Could not validate credentials")
    try:
        form_user: dict = collection.find_one(ObjectId(token_data.sub))
    except Exception as e:
        return FunctionStatus(
            functionName="get_access_token", status=False, section=1, message=f"Mongodb error: {e}")
    if form_user == None or form_user.get('deleted'):
        return FunctionStatus(
            functionName="get_access_token", status=False, section=3, message="User not found")
    if token != form_user.get('accessToken'):
        return FunctionStatus(
            functionName="get_access_token", status=False, section=2, message="Could not validate credentials")
    if form_user.get('disabled'):
        return FunctionStatus(
            functionName="get_access_token", status=False, section=4,message="Inactive user")
    if form_user.get('deleted'):
        return FunctionStatus(status=False, section=5, message="Could not validate credentials")
    return FunctionStatus(status=True, content=form_user)

def get_current_active_superuser(
    current_user: FunctionStatus = Depends(get_current_user)
) -> FunctionStatus:
    if not current_user.status:
        return FunctionStatus(functionName="get_current_active_superuse", status=False)
    return current_user

# ----------------------------------------------------------------------------------------------------------------------------------
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

# async def get_current_user(
#     collection: Collection = Depends(get_db), 
#     token: str = Depends(reusable_oauth2)
#     ) -> FunctionStatus:
#     token_data = get_token_payload(token)
#     if token_data.refresh or token_data.totp:
#         # Refresh token is not a valid access token and TOTP True can only be used to validate TOTP
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
#         return FunctionStatus(status=True, content=form_user)
    
    
# def get_totp_user(collection: Collection = Depends(get_db), token: str = Depends(reusable_oauth2)) -> FunctionReturn:
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
    