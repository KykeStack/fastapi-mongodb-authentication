from schemas.user import SignUpFormIn, SignUpFormOut
from functionTypes.common import FunctionStatus
from dataBase.models.user import CreateUser

from fastapi import APIRouter, status, HTTPException
from fastapi.encoders import jsonable_encoder

from core.security import get_password_hash

from localData.Countries import COUNTRIES
from dataBase.client import session 

router = APIRouter()
collection = session['User']

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
        requested = {"countries": COUNTRIES}
        return jsonable_encoder(requested)
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
        response_description = "Create a new user account"
    )
async def create_user(form: SignUpFormIn):
    """
    Create new user without the need to be logged in.
    """
    mssg = HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service Unavailable"
            )
    if form.privacyPolicy == False:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "The privacy policy is not accepted"
        )
    try:
        find_email = collection.find_one({"email": form.email})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    if find_email != None:
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="email already exists"
            )
    try: 
        find_username = collection.find_one({"username" : form.username})
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=1, message=error)
        print(error_handler)
        raise mssg
    if find_username != None:
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="username already exists"
            )
    encrypted_password = get_password_hash(form.password)
    form.password = encrypted_password.content
    if not encrypted_password.status:
        error_handler = FunctionStatus(status=False, section=0, message=error)
        print(error_handler)
        raise mssg
    signup_form = CreateUser(**form.dict())  
    content = {**signup_form.dict()}      
    try:
        responce = collection.insert_one(content) 
    except Exception as error:
        error_handler = FunctionStatus(status=False, section=1, message=error)
        print(error_handler)
        raise mssg
    content.update({'id': str(responce.inserted_id)})
    return content

if __name__ == "__main__":
    ...