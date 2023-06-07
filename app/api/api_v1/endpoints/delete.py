from schemas.msg import Msg
from schemas.token import WebToken
from schemas.emails import EmailValidation

from fastapi import APIRouter, HTTPException, status, Depends

from functionTypes.common import FunctionStatus
from modules.ValidateData import validate_data
from typing import Union

from typing import Annotated, Any
from bson.objectid import ObjectId
from pymongo.collection import Collection
from pymongo.database import Database

from schemas.token import MagicTokenPayload

from dataBase.client import session
from core.config import settings

from core import security
from api.deps import get_current_active_user, get_magic_token
from utils.emailsMessage import send_delete_account_email

router = APIRouter()
mssg = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )


def get_user_db() -> Union[Collection, Database]:
    try:
        collection = session['User']
        yield collection
    finally:
        session

def get_delete_db() -> Union[Collection, Database]:
    try:
        collection = session['Delete']
        yield collection
    finally:
        session


@router.post(
    "/users/me", 
    response_model=WebToken,  
    response_model_exclude_unset = True,
    response_description= "Delete current User",
    response_model_exclude_none=True
)
async def delete_user(
    current_user: Annotated[FunctionStatus, Depends(get_current_active_user)],
    collection: Collection = Depends(get_user_db)
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
    try: 
        user: dict = collection.update_one({'_id': id}, {'delete'})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="delete_user", status=False, section=1, message=error)
        print(error_handler)
        raise mssg
    tokens = security.create_magic_tokens(subject=id) 
    user_email = user.get('email')
    if settings.EMAILS_ENABLED:
        # Send email with user.email as subject
        data = EmailValidation(email=user_email, subject=user.get('username'), token=tokens[0])
        send_delete_account_email(data=data)
    return {"claim": tokens[1]}


@router.post(
    "/users/me/confirm", 
    response_model=Msg,  
    response_model_exclude_unset = True,
    response_description= "Confirm delete user ",
    response_model_exclude_none=True
)
def confirm_delete_user(
    *,
    obj_in: WebToken,
    collection: Collection = Depends(get_user_db),
    magic_in: FunctionStatus = Depends(get_magic_token)
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
    try: 
        user: dict = collection.find_one(ObjectId(token_user.sub))
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="claim_email", status=False, section=1, message=error)
        print(error_handler)
        raise mssg
    # Test the claims
    test_mssg = HTTPException(status_code=400, detail="Login failed; invalid claim.")
    if (
        (token_user.sub == magic_token.sub)
        or (token_user.fingerprint != magic_token.fingerprint)
        or (user == None)
        or (user.get('disabled'))
    ):
        raise test_mssg
    id = user.get('_id')
    try:
        data_user = collection.delete_one({"_id": id})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="claim_email", status=False, section=3, message=error)
        print(error_handler)
        raise mssg
    if not data_user.acknowledged:
        raise mssg
    return {"msg": "Account deleted successfully."}

@router.get("/tester", response_model=Msg)
def test_endpoint() -> Any:
    """
    Test current endpoint.
    """
    return {"msg": "Message returned ok."}

if __name__ == "__main__":
    ...
