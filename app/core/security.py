from datetime import datetime, timedelta
from typing import Any, Union, Optional, Annotated
from functionTypes.common import FunctionStatus, FunctionReturn

from jose import jwt, JWTError
from passlib.context import CryptContext
from passlib.totp import TOTP
from passlib.exc import TokenError, MalformedTokenError
import uuid

from schemas.totp import NewTOTP
from schemas.user import TokenData

from core.config import settings
from dataBase.client import session
from bson.objectid import ObjectId

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
    
collection = session['User']
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
__cached__ : dict = dict()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")  
totp_factory = TOTP.using(secrets={"1": settings.TOTP_SECRET_KEY}, issuer=settings.SERVER_NAME, alg=settings.TOTP_ALGORITHM)


def create_access_token(*, subject: Union[str, Any], expires_delta: timedelta = None, force_totp: bool = False) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject), "totp": force_totp}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    if not force_totp:
        content = {subject : encoded_jwt}
        __cached__.update(content)
    return encoded_jwt

def create_refresh_token(*, subject: Union[str, Any], expires_delta: timedelta = None) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(seconds=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject), "refresh": True}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def create_magic_tokens(*, subject: Union[str, Any], expires_delta: timedelta = None) -> list[str]:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    fingerprint = str(uuid.uuid4())
    magic_tokens = []
    # First sub is the user.id, to be emailed. Second is the disposable id.
    for sub in [subject, uuid.uuid4()]:
        to_encode = {"exp": expire, "sub": str(sub), "fingerprint": fingerprint}
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        magic_tokens.append(encoded_jwt)
    return magic_tokens

def create_new_totp(*, label: str, uri: Optional[str] = None) -> NewTOTP:
    if not uri:
        totp = totp_factory.new()
    else:
        totp = totp_factory.from_source(uri)
    return NewTOTP(**{
            "secret": totp.to_json(),
            "key": totp.pretty_key(),
            "uri": totp.to_uri(issuer=settings.SERVER_NAME, label=label)})

def verify_totp(*, token: str, secret: str, last_counter: int = None) -> Union[str, bool]:
    """
    token: from user
    secret: totp security string from user in db
    last_counter: int from user in db (may be None)
    """
    try:
        match = totp_factory.verify(token, secret, last_counter=last_counter)
    except (MalformedTokenError, TokenError):
        return False
    else:
        return match.counter

def verify_password(*, plain_password: str, hashed_password: str) -> Union[FunctionStatus, dict]:
    try:
        is_valid_password = pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        return FunctionStatus(
            {"status": False,
             "section": 0, 
             "message": f"CryptContext error: {e}"}
        )
    return {"status": True, "content": is_valid_password}


def get_password_hash(password: str) -> Union[FunctionStatus, dict]:
    try:
        unhash_password = pwd_context.hash(password)
    except Exception as e:
        return FunctionStatus(
            {"status": False,
             "section": 0, 
             "message": f"CryptContext error: {e}"}
        )
    return {"status": True, "content": unhash_password}

def authenticate_user(current_user: str, password: str) -> Union[FunctionReturn, FunctionStatus]:
    try:
        form_user: dict = collection.find_one({
            "$or": [{'username' : current_user}, {'email': current_user}]})
    except Exception as e:
         return FunctionStatus(
             {"status": False,
             "section": 0, 
             "message": f"Mongodb error: {e}"}
        )
    if form_user == None:
        return FunctionStatus(
            {"status": False,
            "section": 1, 
            "message": "User not found in database"}
        )
    unhash_password: dict = verify_password(plain_password=password, hashed_password=form_user.get("password"))
    if not unhash_password.get('content'):
        return FunctionStatus(
            {"status": False,
            "section": 2, 
            "message": "Invalid user password"}
        )
    return {"status": True, "content": form_user}

def get_user(user_id: str) -> Union[FunctionReturn, FunctionStatus]:
    try:
        user: dict = collection.find_one(ObjectId(user_id)) 
    except Exception as e:
        return FunctionStatus(
            {"status": False,
             "section": 0, 
            "message": f"Mongodb error: {e}"}
        )
    if user == None:
        return FunctionStatus(
            {"status": False,
             "section": 1, 
            "message": f"User not found in database"}
        )
    user.update({'id': str(user.get('_id', None))})
    return {"status": True, "content": user}

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> Union[FunctionReturn, FunctionStatus]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: Union[dict, None] = payload.get("sub", None)
        if user_id == None:
            return FunctionStatus(
                {"status": False,
                "section": 0, 
                "message": "Missing information in JWT"}
            )
        # if __cached__.get(user_id) != token:
        #     return FunctionStatus(
        #         {"status": False,
        #         "section": 1, 
        #         "message": "JWT Token is deprecated"}
        #     ) 
        token_data: TokenData = TokenData(userId=user_id)
        user = get_user(user_id=token_data.userId)
        if not user.get('status'):
            return FunctionStatus(
                {"status": False,
                "section": 3, 
                "message": user}
            ) 
    except JWTError as err:
        return FunctionStatus(
            {"status": False,
                "section": 4, 
                "message": err}
        ) 
    return {"status": True, "content": user}

async def get_current_active_user(current_user: Annotated[dict, Depends(get_current_user)]) -> Union[FunctionReturn, FunctionStatus]:
    if not current_user.get('status'):
        return FunctionStatus(
            {"status": False,
                "section": 0, 
                "message": current_user}
        )
    user: dict = current_user.get('content').get('content')
    if user.get('content'):
        return FunctionStatus(
            {"status": False,
                "section": 1, 
                "message": "User is disabled"}
        )
    return {"status": True, "content": user}

