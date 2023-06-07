
from schemas.user import UserOut, UpdateUserData
from schemas.msg import Msg
from schemas.token import WebToken
from schemas.emails import EmailValidation, UserAndEmai

from fastapi import APIRouter, HTTPException, status, Depends

from functionTypes.common import FunctionStatus
from modules.ValidateData import validate_data
from typing import Union
from datetime import datetime

from typing import Annotated, Any
from bson.objectid import ObjectId
from pymongo.collection import Collection
from pymongo.database import Database
from datetime import datetime

from dataBase.models.magix import MagicData, UpdateMagicData
from schemas.token import MagicTokenPayload

from dataBase.client import session
from core.config import settings

from core import security
from api.deps import get_current_active_user, authenticate_user, get_magic_token
from utils.emailsMessage import send_email_validation_email


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

def get_email_db() -> Union[Collection, Database]:
    try:
        collection = session['Email']
        yield collection
    finally:
        session
        
@router.get(
    "/users/me", 
    response_model=UserOut,  
    response_model_exclude_unset = True,
    response_description= "Get user data if not disabled",
    response_model_exclude_none=True
)
async def get_current_user(
    current_user: Annotated[FunctionStatus, Depends(get_current_active_user)]):
    """
    Get current user.
    """
    if not current_user.status:
        if current_user.section == 0:
            user_message: FunctionStatus = current_user.message
            if (
                (user_message.section == 2)
                or (user_message.section == 3)
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Invalid JWT token",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            if (
                (user_message.section == 1)
                or (user_message.section == 0)
            ):
                raise mssg
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail='User is inactive',
                headers={"WWW-Authenticate": "Bearer"}
            )
    return current_user.content


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
    collection: Collection = Depends(get_user_db)
): 
    """
    Update the current user data
    """
    if not current_user_valid.status:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed"
        )  
    current_user: dict = current_user_valid.content
    valid_data = form.dict(exclude_none=True)
    if not valid_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data to update is required"
        )  
    if form.email != None:
        if current_user.get('email') == form.email:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A new email is required"
                )  
        try:
            find_email = collection.find_one({'email': form.email})
        except Exception as error:
            error_handler = FunctionStatus(
                functionName="update_current_user", status=False, section=0, message=error)
            print(error_handler)
            raise mssg
        if find_email != None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already exists"
                )
    if form.username != None:
        if current_user.get('username') == form.username:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A new username is required"
                )  
        try:
            find_username = collection.find_one({"username": form.username})
        except Exception as error:
            error_handler = FunctionStatus(
                functionName="update_current_user", status=False, section=1, message=error)
            print(error_handler)
            raise mssg
        if find_username != None:
            raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username already exists"
                )  
    data = validate_data(current_user, valid_data)
    if not data.status:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=data.message
        )
    user: dict = data.content
    send_email = False
    if form.email != None and current_user.get('emailValidated'):
        tokens = security.create_magic_tokens(subject=current_user.get('_id')) 
        if settings.EMAILS_ENABLED:
            usernme = current_user.get('username')
            if form.username:
                usernme = form.username
            # Send email with user.email as subject
            data = EmailValidation(email=form.email, subject=usernme, token=tokens[0])
            user.update({'emailValidated': False})
            send_email_validation_email(data=data)
            send_email = True
    time: datetime = datetime.now()     
    user.update({'updatedAt' : time})
    try:
        responce = collection.update_one(
            {"_id": current_user.get("_id")}, {"$set": user})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="update_current_user", status=False, section=2, message=error)
        raise mssg 
    if not responce.acknowledged:
        raise mssg
    if responce.modified_count == 0:
        raise mssg
    valid_data.update(
        {'id': str(current_user.get('_id')), 'createdAt': current_user.get('createdAt'), 'updatedAt' : time})
    if send_email:
        return UserAndEmai(userUpdated=valid_data, claim=tokens[1])
    return valid_data
        
# @router.post("/new-totp", response_model=schemas.NewTOTP)
# def request_new_totp(
#     *,
#     current_user: models.User = Depends(get_current_active_user),
# ) -> Any:
#     if not current_user.status:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Login failed"
#         )
#     """
#     Request new keys to enable TOTP on the user account.
#     """
#     obj_in = security.create_new_totp(label=current_user.email)
#     # Remove the secret ...
#     obj_in.secret = None
#     return obj_in


@router.post(
    "/users/me/verify/email", 
    response_model=WebToken,  
    response_model_exclude_unset = True,
    response_description= "Verify user email",
    response_model_exclude_none=True
)
async def verify_user_email(
    current_user: Annotated[FunctionStatus, Depends(get_current_active_user)],
    collection: Collection = Depends(get_email_db)  
):
    """
    Verify user email after signup
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
    if user.get('emailValidated'):
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail='Email is already verify',
                headers={"WWW-Authenticate": "Bearer"}
            )
    tokens = security.create_magic_tokens(subject=user.get('_id')) 
    user_email = user.get('email')
    try:
        update_content = UpdateMagicData(claimToken=tokens[1], updatedAt=datetime.now())
        responce = collection.update_one(
            {"foreignId": user.get("_id")}, {"$set": {**update_content.dict()}})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName='verify_user_email', status=False, section=1, message=error)
        print(error_handler)
        raise mssg
    if not responce.acknowledged:
        error_handler = FunctionStatus(
            functionName='verify_user_email', status=False, section=2, message="Update calim not acknowledged")
        raise mssg
    if responce.modified_count == 0:
        content = MagicData(foreignId=user.get('_id'), email=user_email, claimToken=tokens[1])
        try:
            responce = collection.insert_one({**content.dict()})
        except Exception as error:
            error_handler = FunctionStatus(
                functionName='verify_user_email', status=False, section=3, message=error)
            print(error_handler)
            raise mssg
        if not responce.acknowledged:
            error_handler = FunctionStatus(
                functionName='verify_user_email', status=False, section=2, message="Update calim not acknowledged")
            raise mssg
    if settings.EMAILS_ENABLED:
        # Send email with user.email as subject
        data = EmailValidation(email=user_email, subject=user.get('username'), token=tokens[0])
        send_email_validation_email(data=data)
    return {"claim": tokens[1]}


@router.post(
    "/users/me/claim/email", 
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
    # Check if email is already validated
    if user.get('emailValidated'):
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail='Email is already verify',
                headers={"WWW-Authenticate": "Bearer"}
            )
    try: 
        email_db: dict = email_collection.find_one({"foreignId": user.get('_id')})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="claim_email", status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if email_db == None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )  
    if email_db.get('claimToken') != obj_in.claim:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Token",
        )
    try:
        data_user = collection.update_one({"_id": id}, {"$set": {"updatedAt": datetime.now(), "emailValidated": True}})
        update_magic = UpdateMagicData(claimToken="", updatedAt=datetime.now())
        magic_data = email_collection.update_one({"foreignId":id}, {"$set": {**update_magic.dict()}})
    except Exception as error:
        error_handler = FunctionStatus(
            functionName="claim_email", status=False, section=3, message=error)
        print(error_handler)
        raise mssg
    if not data_user.acknowledged or not magic_data.acknowledged:
        raise mssg
    return {"msg": "Email verify successfully."}

@router.get("/tester", response_model=Msg)
def test_endpoint() -> Any:
    """
    Test current endpoint.
    """
    return {"msg": "Message returned ok."}

if __name__ == "__main__":
    ...
