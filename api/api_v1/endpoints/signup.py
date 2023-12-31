from schemas.user import SignUpFormIn, SignUpFormOut
from functionTypes.common import FunctionStatus
from dataBase.models.user import CreateUser

from localData.Countries import COUNTRIES

from fastapi import APIRouter, HTTPException, status, Depends

from crud.user import unique_email_username
from fastapi.encoders import jsonable_encoder
from api.deps import get_password_hash, get_user_db
from utils.emailsMessage import send_new_account_email

from core.config import settings

from pymongo.collection import Collection

UNAUTHORIZED_MESSAGE = HTTPException(status_code=401, detail="Could not Validate Credentials")

router = APIRouter()

@router.get(
    "/countries", 
    status_code = status.HTTP_200_OK, 
    response_description = "Get list of available countries"
)
async def list_of_countries():
    """
    Get list of available countries 
    """
    try:
        return jsonable_encoder({"countries": COUNTRIES})
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            message="Impossible to access the list of countries"
        )


@router.post(
        "/",
        status_code = status.HTTP_201_CREATED, 
        response_model = SignUpFormOut,
        response_model_exclude_unset = True,
        response_model_exclude_none= True,
        response_description = "Create a new user account"
    )
async def create_user(form: SignUpFormIn, collection: Collection = Depends(get_user_db)):
    """
    Create new user without the need to be logged in.
    """
    unique_email_username(collection=collection, email=form.email, username=form.username)
    encrypted_password = get_password_hash(form.password)
    form.password = encrypted_password.content
    
    if not encrypted_password.status:
        raise UNAUTHORIZED_MESSAGE
    
    signup_form = CreateUser(**form.dict())  
    content = {**signup_form.dict()}      
    try:
        responce = collection.insert_one(content)
    except Exception as error:
        raise UNAUTHORIZED_MESSAGE
    
    if not responce.acknowledged:
        raise UNAUTHORIZED_MESSAGE
    
    content.update({'id': str(responce.inserted_id)})
    if settings.EMAILS_ENABLED:
        send_new_account_email(email_to=form.email, username=form.username, password=form.password)
    return content

if __name__ == "__main__":
    ...