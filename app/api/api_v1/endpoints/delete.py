from schemas.msg import Msg
from schemas.token import WebToken
from schemas.emails import EmailValidation

from fastapi import APIRouter, HTTPException, status, Depends

from functionTypes.common import FunctionStatus
from typing import Annotated, Any

from bson.objectid import ObjectId
from pymongo.collection import Collection
from schemas.token import MagicTokenPayload

from core.config import settings

from core import security
from crud.tokens import set_db_tokens, verify_token
from crud.user import delete_user, find_one_document
from api.deps import get_current_active_user, get_magic_token, get_user_db, get_delete_db
from utils.emailsMessage import send_delete_account_email

router = APIRouter()
mssg = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )

@router.post(
    "/users/me", 
    response_model=WebToken,  
    response_model_exclude_unset = True,
    response_description= "Delete current User",
    response_model_exclude_none=True
)
async def delete_user_db(
    current_user: Annotated[FunctionStatus, Depends(get_current_active_user)],
    collection: Collection = Depends(get_delete_db)
):
    """
    Delete user account
    """
    if not current_user.status:
        if current_user.section == 0:
            print(current_user.message)
            raise mssg
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail='User is inactive',
                headers={"WWW-Authenticate": "Bearer"}
            )
    user = current_user.content
    id = user.get('_id')
    user_email = user.get('email')
    tokens = security.create_magic_tokens(subject=id) 
    set_db_tokens(collection=collection, token=tokens[1], id=id)
    if settings.EMAILS_ENABLED:
        # Send email with user.email as subject
        data = EmailValidation(email=user_email, subject=user.get('username'), token=tokens[0])
        send_delete_account_email(data=data)
    return {"claim": tokens[1]}


@router.post(
    "/me/confirm", 
    response_model=Msg,  
    response_model_exclude_unset = True,
    response_description= "Confirm delete user ",
    response_model_exclude_none=True
)
def confirm_delete_user(
    *,
    obj_in: WebToken,
    magic_in: FunctionStatus = Depends(get_magic_token),
    collection: Collection = Depends(get_user_db),
    delete_collection: Collection = Depends(get_delete_db)
) -> Any:
    """
    Second step of a 'delete user account'.
    """
    claim_in = get_magic_token(token=obj_in.claim)
    if not claim_in.status or not magic_in.status:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    token_user: MagicTokenPayload = magic_in.content
    magic_token: MagicTokenPayload = claim_in.content
    #Get the user
    user = find_one_document(collection=collection, query=ObjectId(token_user.sub))
    # Test the claims
    id = user.get('_id')
    test_mssg = HTTPException(status_code=400, detail="Login failed; invalid claim..")
    if (
        (token_user.sub == magic_token.sub)
        or (token_user.fingerprint != magic_token.fingerprint)
        or (user.get('disabled'))
    ):
        raise test_mssg
     # Verify if Toke is already claim
    verify_token(collection=delete_collection, id=id, claim=obj_in.claim)
    # Delete the user from db
    delete_user(collection=collection, id=id)
    return {"msg": "Account deleted successfully."}

if __name__ == "__main__":
    ...
