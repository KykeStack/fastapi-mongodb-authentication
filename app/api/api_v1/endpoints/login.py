from typing import Annotated, Any, Union, Dict
from pydantic import EmailStr

from fastapi import APIRouter, HTTPException, status, Body, Depends
from fastapi.security import OAuth2PasswordRequestForm

from schemas.token import WebToken, Token
from schemas.msg import Msg
from api.deps import get_magic_token, get_refresh_user
from core import security

from core.config import settings
from dataBase.client import session

from bson.objectid import ObjectId
from pymongo.collection import Collection
from pymongo.database import Database

from functionTypes.common import FunctionStatus
from schemas.token import MagicTokenPayload

from utils.emailsMessage import (
    send_reset_password_email,
    send_magic_login_email,
)

router = APIRouter()

"""
https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md
Specifies minimum criteria:
    - Change password must require current password verification to ensure that it's the legitimate user.
    - Login page and all subsequent authenticated pages must be exclusively accessed over TLS or other strong transport.
    - An application should respond with a generic error message regardless of whether:
        - The user ID or password was incorrect.
        - The account does not exist.
        - The account is locked or disabled.
    - Code should go through the same process, no matter what, allowing the application to return in approximately 
      the same response time.
    - In the words of George Orwell, break these rules sooner than do something truly barbaric.

See `security.py` for other requirements.
"""

def get_user_db() -> Union[Collection, Database]:
    try:
        collection = session['User']
        yield collection
    finally:
        session
        
def get_magic_db() -> Union[Collection, Database]:
    try:
        collection = session['Magic']
        yield collection
    finally:
        session

mssg = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service Unavailable"
        )

@router.post("/magic/{email}" , response_model=WebToken)
def login_with_magic_link(
    *, 
    email: EmailStr, 
    user_collection: Collection = Depends(get_user_db), 
    magic_collection: Collection = Depends(get_magic_db)) -> Any:
    """
    First step of a 'magic link' login. Check if the user exists and generate a magic link. Generates two short-duration
    jwt tokens, one for validation, one for email.
    """
    try:
        user: dict = user_collection.find_one({'email': email})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg  
    if user == None:
      raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )  
    if user.get('disabled'):
        # Still permits a timed-attack, but does create ambiguity.
        raise HTTPException(status_code=400, detail="A link to activate your account has been emailed.")
    tokens = security.create_magic_tokens(subject=user.get('_id')) 
    
    user_email = user.get('email')
    if settings.EMAILS_ENABLED and user_email:
        # Send email with user.email as subject
        send_magic_login_email(email_to=user_email, token=tokens[0])
    return {"claim": tokens[1]}


@router.post("/claim", response_model=Token)
def validate_magic_link(
    *,
    obj_in: WebToken,
    collection: Collection = Depends(get_user_db),
    magic_in: FunctionStatus = Depends(get_magic_token),
) -> Any:
    """
    Second step of a 'magic link' login.
    """
    claim_in = get_magic_token(token=obj_in.claim)
    if not claim_in.status or not magic_in.status:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    user: MagicTokenPayload = magic_in.content
    magic_token: MagicTokenPayload = claim_in.content
    #Get the user
    try: 
        found_user: dict = collection.find_one(ObjectId(user.sub))
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    id = found_user.get('_id')
    # Test the claims
    test_mssg = HTTPException(status_code=400, detail="Login failed; invalid claim.")
    if (
        (user.sub == magic_token.sub)
        or (user.fingerprint != magic_token.fingerprint)
        or not found_user
        or found_user.get('disabled')
    ):
        raise test_mssg
    # Validate that the email is the user's
    if not found_user.get('emailValidated'):
        try:
            found_user_email: dict = collection.find_one({"email": found_user.get('email')})
        except Exception as error:
            error_handler = FunctionStatus(status=False, section=0, message=error)
            print(error_handler)
            raise mssg
        if found_user_email == None:
            raise test_mssg
        if not str(id) == str(found_user_email.get('_id')):
            raise test_mssg
        
    # Check if totp active
    refresh_token = None
    force_totp = True
    if not found_user.get('totpSecret'):
        # No TOTP, so this concludes the login validation
        force_totp = False
        refresh_token = security.create_refresh_token(subject=id)
        try:
            data = collection.update_one({"_id": ObjectId(id)}, {"$set": {"refreshToken": refresh_token}})
        except Exception as error:
            error_handler = FunctionStatus(status=False, section=0, message=error)
            print(error_handler)
            raise mssg
        if not data.acknowledged:
            raise mssg
    return {
        "access_token": security.create_access_token(subject=id, force_totp=force_totp),
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@router.post("/oauth", response_model=Token)
def login_with_oauth2(form_data: OAuth2PasswordRequestForm = Depends(), collection: Collection = Depends(get_user_db)) -> Any:
    """
    First step with OAuth2 compatible token login, get an access token for future requests.
    """
    valid_username = form_data.username.lower()
    user: FunctionStatus = security.authenticate_user(valid_username, form_data.password)
    if not form_data.password or not user.status:
        raise HTTPException(status_code=400, detail="Login failed; incorrect email or password")
    found_user: dict = user.content
    # Check if totp active
    refresh_token = None
    force_totp = True
    if not found_user.get('totpSecret'):
        id = found_user.get('_id')
        # No TOTP, so this concludes the login validation
        force_totp = False
        refresh_token = security.create_refresh_token(subject=id)
        try:
            data = collection.update_one({"_id": ObjectId(id)}, {"$set": {"refreshToken": refresh_token}})
        except Exception as error:
            error_handler = FunctionStatus(status=False, section=0, message=error)
            print(error_handler)
            raise mssg
        if not data.acknowledged:
            raise mssg
    return {
        "access_token": security.create_access_token(subject=id, force_totp=force_totp),
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


# @router.post("/totp", response_model=Token)
# def login_with_totp(
#     *,
#     db: Session = Depends(deps.get_user_db),
#     totp_data: schemas.WebToken,
#     current_user: models.User = Depends(deps.get_totp_user),
# ) -> Any:
#     """
#     Final validation step, using TOTP.
#     """
#     new_counter = security.verify_totp(
#         token=totp_data.claim, secret=current_user.totp_secret, last_counter=current_user.totp_counter
#     )
#     if not new_counter:
#         raise HTTPException(status_code=400, detail="Login failed; unable to verify TOTP.")
#     # Save the new counter to prevent reuse
#     current_user = crud.user.update_totp_counter(db=db, db_obj=current_user, new_counter=new_counter)
#     refresh_token = security.create_refresh_token(subject=current_user.id)
#     crud.token.create(db=db, obj_in=refresh_token, user_obj=current_user)
#     return {
#         "access_token": security.create_access_token(subject=current_user.id),
#         "refresh_token": refresh_token,
#         "token_type": "bearer",
#     }


# @router.put("/totp", response_model=schemas.Msg)
# def enable_totp_authentication(
#     *,
#     db: Session = Depends(deps.get_user_db),
#     data_in: schemas.EnableTOTP,
#     current_user: models.User = Depends(deps.get_current_active_user),
# ) -> Any:
#     """
#     For validation of token before enabling TOTP.
#     """
#     if current_user.hashed_password:
#         user = crud.user.authenticate(db, email=current_user.email, password=data_in.password)
#         if not data_in.password or not user:
#             raise HTTPException(status_code=400, detail="Unable to authenticate or activate TOTP.")
#     totp_in = security.create_new_totp(label=current_user.email, uri=data_in.uri)
#     new_counter = security.verify_totp(
#         token=data_in.claim, secret=totp_in.secret, last_counter=current_user.totp_counter
#     )
#     if not new_counter:
#         raise HTTPException(status_code=400, detail="Unable to authenticate or activate TOTP.")
#     # Enable TOTP and save the new counter to prevent reuse
#     current_user = crud.user.activate_totp(db=db, db_obj=current_user, totp_in=totp_in)
#     current_user = crud.user.update_totp_counter(db=db, db_obj=current_user, new_counter=new_counter)
#     return {"msg": "TOTP enabled. Do not lose your recovery code."}


# @router.delete("/totp", response_model=schemas.Msg)
# def disable_totp_authentication(
#     *,
#     db: Session = Depends(deps.get_user_db),
#     data_in: schemas.UserUpdate,
#     current_user: models.User = Depends(deps.get_current_active_user),
# ) -> Any:
#     """
#     Disable TOTP.
#     """
#     if current_user.hashed_password:
#         user = crud.user.authenticate(db, email=current_user.email, password=data_in.original)
#         if not data_in.original or not user:
#             raise HTTPException(status_code=400, detail="Unable to authenticate or deactivate TOTP.")
#     crud.user.deactivate_totp(db=db, db_obj=current_user)
#     return {"msg": "TOTP disabled."}


@router.post("/refresh", response_model=Token)
def refresh_token(
    current_user: Annotated[FunctionStatus, Depends(get_refresh_user)],
    collection: Collection = Depends(get_user_db)
) -> Any:
    """
    Refresh tokens for future requests
    """
    if not current_user.status:
        if current_user.section == 1:
            raise mssg
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=current_user.message,
        )
    id = current_user.content.get('_id')
    refresh_token = security.create_refresh_token(subject=id)
    try:
        data = collection.update_one({"_id": ObjectId(id)}, {"$set": {"refreshToken": refresh_token}})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if not data.acknowledged:
        raise mssg
    return {
        "access_token": security.create_access_token(subject=id),
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/revoke", response_model=Msg)
def revoke_token(
    current_user: Annotated[FunctionStatus, Depends(get_refresh_user)],
    collection: Collection = Depends(get_user_db)
) -> Any:
    """
    Revoke a refresh token
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
        data = collection.update_one({"_id": ObjectId(id)}, {"$set": {"refreshToken": ""}})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if not data.acknowledged:
        raise mssg
    return {"msg": "Token revoked"}


@router.post("/recover/{email}", response_model=Union[WebToken, Msg])
def recover_password(
    email: str, 
    collection: Collection = Depends(get_user_db)
    ) -> Any:
    """
    Password Recovery
    """
    try:
        user: dict = collection.find_one({"email": email})
        
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if user != None and not user.get('disabled'):
        tokens = security.create_magic_tokens(subject=user.get('_id'))
        if settings.EMAILS_ENABLED:
            send_reset_password_email(email_to=user.get('email'), email=email, token=tokens[0])
            return {"claim": tokens[1]}
    return {"msg": "If that login exists, we'll send you an email to reset your password."}


@router.post("/reset", response_model=Msg)
def reset_password(
    *,
    collection: Collection = Depends(get_user_db),
    new_password: str = Body(...),
    claim: str = Body(...),
    magic_in: FunctionStatus = Depends(get_magic_token),
) -> Any:
    """
    Reset password
    """
    claim_in = get_magic_token(token=claim)
    if not claim_in.status or not magic_in.status:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    user: MagicTokenPayload = magic_in.content
    magic_token: MagicTokenPayload = claim_in.content
    # Get the user
    try: 
        found_user: dict = collection.find_one(ObjectId(user.sub))
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    
    # Test the claims
    test_mssg = HTTPException(status_code=400, detail="Password update failed; invalid claim.")
    if (
        (user.sub == magic_token.sub)
        or (user.fingerprint != magic_token.fingerprint)
        or not found_user
        or found_user.get('disabled')
    ):
        raise test_mssg
    password_defer = security.verify_password(plain_password=new_password, hashed_password=found_user.get('password'))
    if not password_defer.status and password_defer.section == 0:
        print(password_defer)
        raise test_mssg
    
    if password_defer.content == True:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Password update failed; new password is the same as the old one."
        )
    # Update the password
    hashed_password = security.get_password_hash(new_password)
    if not hashed_password.status:
        print(hashed_password)
        raise test_mssg
    id = found_user.get('_id')
    try:
        responce = collection.update_one(
            {"_id": id},
                {"$set": {'password' : hashed_password.content}}
                )
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if responce.raw_result.get('nModified') != 1:
        raise mssg 
    return {"msg": "Password updated successfully."}
