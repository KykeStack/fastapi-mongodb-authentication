from datetime import datetime, timedelta
from typing import Any, Union, Optional

from jose import jwt
from passlib.totp import TOTP
from passlib.exc import TokenError, MalformedTokenError
import uuid

from schemas.totp import NewTOTP

from core.config import settings
from dataBase.client import session

totp_factory = TOTP.using(secrets={"1": settings.TOTP_SECRET_KEY}, issuer=settings.SERVER_NAME, alg=settings.TOTP_ALGORITHM)

def create_access_token(*, subject: Union[str, Any], expires_delta: timedelta = None, force_totp: bool = False, admin: Optional[bool] = False) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject), "totp": force_totp, "admin": admin}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(*, subject: Union[str, Any], expires_delta: timedelta = None) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject), "refresh": True}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def create_magic_tokens(*, subject: Union[str, Any], expires_delta: timedelta = None) -> list[str]:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
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
    
if __name__ == "__main__":
    ...