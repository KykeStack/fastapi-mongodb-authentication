from schemas.user import UserOut, UpdateUserData
from schemas.msg import Msg
from schemas.token import WebToken
from schemas.emails import EmailValidation, UserAndEmai

from fastapi import APIRouter, HTTPException, status, Depends

from functionTypes.common import FunctionStatus
from modules.ValidateData import validate_data
from typing import Union

from typing import Annotated, Any
from bson.objectid import ObjectId
from pymongo.collection import Collection
from schemas.token import MagicTokenPayload

from core.config import settings

from core import security
from crud.user import update_user, find_one_document
from crud.tokens import set_db_tokens, verify_token
from crud.user import unique_email_username
from api.deps import get_current_active_user, get_magic_token, get_user_db, get_email_db
from utils.emailsMessage import send_email_validation_email

UNAUTHORIZED_MESSAGE = HTTPException(status_code=401, detail="Could not Validate Credentials")

router = APIRouter()

@router.get(
    "/users/me", 
    response_model=UserOut,  
    response_model_exclude_unset = True,
    response_description= "Get user data if not disabled",
    response_model_exclude_none=True
)
async def get_current_user(
    user: Annotated[FunctionStatus, Depends(get_current_active_user)]):
    """
    Get current user.
    """
    if not user.status:
        raise UNAUTHORIZED_MESSAGE
    return user.content


@router.put(
    "/users/me", 
    response_description= "Update the current user data",
    response_model= Union[UserOut, UserAndEmai],
    response_model_exclude_none=True,
    response_model_exclude_unset=True
)
async def update_current_user(
    current_user_valid: Annotated[FunctionStatus, Depends(get_current_active_user)],
    form: UpdateUserData,
    collection: Collection = Depends(get_user_db),
    emails_collection: Collection = Depends(get_email_db)
): 
    """
    Update the current user data
    """
    if not current_user_valid.status:
        print(current_user_valid.message)
        raise UNAUTHORIZED_MESSAGE
        
    user: dict = current_user_valid.content
    valid_data = form.dict(exclude_none=True)
    
    if not valid_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data to update is required"
        )  
        
    if form.username != None or form.username != None:
        if user.get('username') == form.username:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A new username is required"
                )
        if user.get('email') == form.email:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A new email is required"
                )     
        unique_email_username(collection=collection, email=form.email, username=form.username)

    data = validate_data(user, valid_data)
    if not data.status:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=data.message
        )
    
    content: dict = data.content
    send_email = False
    
    if form.email != None and user.get('emailValidated'):
        tokens = security.create_magic_tokens(subject=user.get('_id'))
        # Set the token on db 
        set_db_tokens(collection=emails_collection, token=tokens[0], id=user.get('_id'))
        if settings.EMAILS_ENABLED:
            usernme = user.get('username')
            if form.username:
                usernme = form.username
            # Send email with user.email as subject
            data = EmailValidation(email=form.email, subject=usernme, token=tokens[0])
            content.update({'emailValidated': False})
            send_email_validation_email(data=data)
            send_email = True
            
    updated = update_user(collection=collection, id=user.get('_id'), data=content)
    valid_data.update({'id': str(user.get('_id')), 'createdAt': user.get('createdAt'), 'updatedAt' : updated})
    
    if send_email:
        return UserAndEmai(userUpdated=valid_data, claim=tokens[1])
    
    return valid_data


@router.post(
    "/me/verify/email", 
    response_model=WebToken,  
    response_model_exclude_unset = True,
    response_description= "Verify user email",
    response_model_exclude_none=True
)
async def verify_user_email(
    user: Annotated[FunctionStatus, Depends(get_current_active_user)],
    collection: Collection = Depends(get_email_db)  
):
    """
    Verify user email after signup
    """
    if not user.status:
        raise UNAUTHORIZED_MESSAGE
    
    user = user.content
    if user.get('emailValidated'):
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail='Email is already verify'
            )
    
    user_email = user.get('email')
    id = user.get('_id')
    tokens = security.create_magic_tokens(subject=id)
    
    # Set the claim token on db
    set_db_tokens(collection=collection, token=tokens[1], id=id)
    if settings.EMAILS_ENABLED:
        # Send email with user.email as subject
        data = EmailValidation(email=user_email, subject=user.get('username'), token=tokens[0])
        send_email_validation_email(data=data)
    return {"claim": tokens[1]}


@router.post(
    "/me/claim/email", 
    response_model=Msg,  
    response_model_exclude_unset = True,
    response_description= "Claim email verification",
    response_model_exclude_none=True
)
def claim_email(
    *,
    obj_in: WebToken,
    collection: Collection = Depends(get_user_db),
    magic_in: FunctionStatus = Depends(get_magic_token),
    email_collection: Collection = Depends(get_email_db)
) -> Any:
    """
    Second step of a 'email verification'.
    """
    claim_in = get_magic_token(token=obj_in.claim)
    if not claim_in.status or not magic_in.status:
        raise UNAUTHORIZED_MESSAGE
    
    token_user: MagicTokenPayload = magic_in.content
    magic_token: MagicTokenPayload = claim_in.content
    #Get the user
    user = find_one_document(collection=collection, query=ObjectId(token_user.sub))
    # Check if email is already validated
    if user.get('emailValidated'):
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail='Email is already verify'
            )
        
    # Test the claims
    if (
        (token_user.sub == magic_token.sub)
        or (token_user.fingerprint != magic_token.fingerprint)
        or (user.get('disabled'))
    ):
        raise UNAUTHORIZED_MESSAGE
    # Verify if Toke is already claim
    verify_token(collection=email_collection, id=user.get('_id'), claim=obj_in.claim)
    # Update user tokens
    data = {"emailValidated": True}
    update_user(collection=collection, id=user.get('_id'), data=data)
    # Deprecate claim token
    set_db_tokens(collection=email_collection, token='', id=user.get('_id'))
    return {"msg": "Email verify successfully."}

if __name__ == "__main__":
    ...
