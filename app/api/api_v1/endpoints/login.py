from typing import Annotated, Any, Union
from pydantic import EmailStr

from fastapi import APIRouter, HTTPException, status, Body, Depends
from fastapi.security import OAuth2PasswordRequestForm

from schemas.token import WebToken, Token
from schemas.token import AccessToken
from schemas.msg import Msg

from core import security

from core.config import settings

from bson.objectid import ObjectId
from pymongo.collection import Collection

from functionTypes.common import FunctionStatus
from schemas.token import MagicTokenPayload

from crud.tokens import set_db_tokens, verify_token
from crud.user import verify_email, update_user, find_one_document

from utils.emailsMessage import (
    send_reset_password_email,
    send_magic_login_email,
)

from api.deps import (
    get_magic_token, 
    get_refresh_user, 
    authenticate_user,
    verify_password,
    get_password_hash,
    get_user_db,
    get_magic_db,
    get_password_db
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




mssg = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service Unavailable"
        )

@router.post("/magic/{email}" , response_model=Union[WebToken,Msg])
def login_with_magic_link(
    *, 
    email: EmailStr, 
    user_collection: Collection = Depends(get_user_db), 
    magic_collection: Collection = Depends(get_magic_db)
    ) -> Any:
    """
    First step of a 'magic link' login. Check if the user exists and generate a magic link. Generates two short-duration
    jwt tokens, one for validation, one for email.
    """
    user = find_one_document(collection=user_collection, query={'email': email}, return_value=True)
    if user == None:
        return {"msg": "If that login exists, we'll send you an email to reset your password."}
    if user.get('disabled'):
        # Still permits a timed-attack, but does create ambiguity.
        raise HTTPException(status_code=400, detail="A link to activate your account has been emailed.")
    id = user.get('_id')
    tokens = security.create_magic_tokens(subject=id) 
    set_db_tokens(collection=magic_collection, token=tokens[1], id=id)
    if settings.EMAILS_ENABLED:
        user_email = user.get('email')
        # Send email with user.email as subject
        send_magic_login_email(email_to=user_email, token=tokens[0])
    return {"claim": tokens[1]}


@router.post("/claim", response_model=Token)
def validate_magic_link(
    *,
    obj_in: WebToken,
    collection: Collection = Depends(get_user_db),
    magic_in: FunctionStatus = Depends(get_magic_token),
    magic_collection: Collection = Depends(get_magic_db)
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
    user_token = magic_in.content
    magic_token = claim_in.content
    test_mssg = HTTPException(status_code=400, detail="Login failed; invalid claim.")
    #Get the user
    user = find_one_document(collection=collection, query=ObjectId(user_token.sub))
    # Test the claims
    if (
        (user_token.sub == magic_token.sub)
        or (user_token.fingerprint != magic_token.fingerprint)
        or (user.get('disabled'))
    ):
        raise test_mssg
    id = user.get('_id')
    email = user.get('email')
    # Validate that the email is the user's
    if not user.get('emailValidated'):
        verify_email(collection=collection, email=email, id=id)
    # Verify if token has been claim before
    verify_token(collection=magic_collection, id=id, claim=obj_in.claim)
    # Check if totp active
    refresh_token = None
    force_totp = True
    if not user.get('totpSecret'):
        # No TOTP, so this concludes the login validation
        force_totp = False
        refresh_token = security.create_refresh_token(subject=id)
        access_token = security.create_access_token(subject=id, force_totp=force_totp)
        # Set the Refresh and Access Token on db
        data = {"refreshToken": refresh_token, "accessToken": access_token}
        update_user(collection=collection, id=id, data=data)
        # Also deprecate the Claim
        set_db_tokens(collection=magic_collection, token="", id=id)
    return {
        "id": str(id),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
    
@router.post(
    "/token", 
    response_model=AccessToken,
    response_description="Generate a new JWT token"    
)
async def signin_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    collection: Collection = Depends(get_user_db)
):
    """
    Generate only a JWT access token 
    """
    user: FunctionStatus = authenticate_user(form_data.username, form_data.password)
    if not user.status:
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed; incorrect email or password"
            ) 
    id = user.content.get('_id')
    access_token = security.create_access_token(subject=id)
    data = {"accessToken": access_token}
    update_user(collection=collection, id=id, data=data)
    return{
        "id" : str(id), 
        "accessToken": access_token, 
        "tokenType": "bearer"
    } 

@router.post("/token/refresh", response_model=Token)
def login_with_oauth2(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    collection: Collection = Depends(get_user_db)
) -> Any:
    """
    First step with OAuth2 compatible token login, get an access token for future requests.
    """
    valid_username = form_data.username.lower()
    user: FunctionStatus = authenticate_user(valid_username, form_data.password)
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
        access_token = security.create_access_token(subject=id, force_totp=force_totp)
        # Set the Refresh and Access Token on db
        data = {"refreshToken": refresh_token, "accessToken": access_token}
        update_user(collection=collection, id=id, data=data)
    return {
        "id": str(id),
        "access_token": access_token,
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
    # if not current_user.status:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="Login failed"
    #     )
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
    # if not current_user.status:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="Login failed"
    #     )
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
    access_token = security.create_access_token(subject=id)
    data = {"refreshToken": refresh_token, "accessToken": access_token}
    update_user(collection=collection, id=id, data=data)
    return {
        "id": str(id),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/revoke/refresh", response_model=Msg)
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
    update_user(collection=collection, id=id, data={'refreshToken': ""})
    return {"msg": "Token revoked"}


@router.post("/recover/{email}", response_model=Union[WebToken, Msg])
def recover_password(
    email: str, 
    user_collection: Collection = Depends(get_user_db),
    password_collection: Collection = Depends(get_password_db)
    ) -> Any:
    """
    Password Recovery
    """
    # Find if email exist on db
    user = find_one_document(collection=user_collection, query={"email": email}, return_value=True)
    if user == None:
        return {"msg": "If that email exists, we'll send you an email to reset your password."}
    if user.get('disabled'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Recover failed; invalid claim."
        )
    id = user.get("_id")
    # Validate that the email is the user's
    if not user.get('emailValidated'):
        verify_email(collection=user_collection, email=email, id=id)
    # Get those tokens, baby!!
    tokens = security.create_magic_tokens(subject=id)     
    # Set the Token db to be claim 
    set_db_tokens(collection=password_collection, token=tokens[1], id=id)
    if settings.EMAILS_ENABLED:
        send_reset_password_email(email_to=email, username=user.get('username'), token=tokens[0])
    return {"claim": tokens[1]}
    
    
@router.post("/reset", response_model=Msg)
def reset_password(
    *,
    collection: Collection = Depends(get_user_db),
    new_password: str = Body(...),
    claim: str = Body(...),
    magic_in: FunctionStatus = Depends(get_magic_token),
    pasword_collection: Collection = Depends(get_password_db)
) -> Any:
    """
    Reset password
    """
    claim_in = get_magic_token(token=claim)
    if not claim_in.status or not magic_in.status:
        print(FunctionStatus(
            status=False,
            message={"claim_in": claim_in.message, "magic_in": magic_in.message}
        ))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    token_user: MagicTokenPayload = magic_in.content
    magic_token: MagicTokenPayload = claim_in.content
    # Get the user
    user = find_one_document(collection=collection, query=ObjectId(token_user.sub))
    test_mssg = HTTPException(status_code=400, detail="Password update failed; invalid claim.")
    # Test the claims
    if (
        (token_user.sub == magic_token.sub)
        or (token_user.fingerprint != magic_token.fingerprint)
        or (user.get('disabled'))
    ):
        raise test_mssg
    id = user.get('_id')
    password_defer = verify_password(
        plain_password=new_password, hashed_password=user.get('password'))
    if password_defer.content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Password update failed; new password is the same as the old one."
        )
    if password_defer.section == 0:
        print(password_defer)
        raise test_mssg
    # Verify if token has been claim before
    verify_token(collection=pasword_collection, id=id, claim=claim)
    # Update the password
    hashed_password = get_password_hash(new_password)
    if not hashed_password.status:
        print(hashed_password)
        raise test_mssg
    # Deprecate the Claim and update the user password
    set_db_tokens(collection=pasword_collection, token='', id=id)
    # Update user password 
    data = {'password' : hashed_password.content}
    update_user(collection=collection, id=id, data=data)
    return {"msg": "Password updated successfully."}


if __name__ == "__main__":
    ...
