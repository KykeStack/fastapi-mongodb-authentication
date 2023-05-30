from schemas.user import SignUpFormIn, SignUpFormOut
from fastapi import APIRouter, status, HTTPException
from fastapi.encoders import jsonable_encoder

from localData.Countries import COUNTRIES
from dataBase.client import session 

from core.security import get_password_hash

from datetime import datetime

router = APIRouter()
collection = session['User']


"""Get list of available countries

Raises:
    HTTPException: 404_NOT_FOUND -> if data not available
Returns:
    _type_: 200_OK -> if success
"""
@router.get(
    "/countries", 
    status_code = status.HTTP_200_OK, 
    response_description = "Get list of available countries"
)
async def list_of_countries():
    try:
        requested = {"countries": COUNTRIES}
        return jsonable_encoder(requested)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            message="Impossible to access the list of countries"
        )

"""Create a new user

Raises:
    HTTPException: 400 -> The privacy policy is not accepted
    HTTPException: 409 -> Email or username alredy exist

Returns:
    HTTPResponce : 201 -> User created, and user gather information 
"""
@router.post(
        "/",
        status_code = status.HTTP_201_CREATED, 
        response_model = SignUpFormOut,
        response_model_exclude_unset = True,
        response_description = "Create a new user account"
    )
async def create_user(form: SignUpFormIn):
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
    except Exception as err:
        print(
            {"status": False,
                "section": 0, 
                "message": err})
        raise mssg
    if find_email != None:
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="email already exists"
            )
    try: 
        find_username = collection.find_one({"username" : form.username})
    except Exception as err:
        print(
            {"status": False,
                "section": 1, 
                "message": err})
        raise mssg
    if find_username != None:
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="username already exists"
            )
        
    time = datetime.now()
    encrypted_password = get_password_hash(form.password)
    if not encrypted_password.get('status'):
        print(
            {"status": False,
                "section": 2, 
                "message": encrypted_password.get('message')})
        raise mssg
    signup_form = {
        **form.dict(),
        "password": encrypted_password.get('content'),
        "emailValidated": False, 
        "totpSecret": None,
        "totpCounter": None,
        "refreshTokens": [],
        "disabled": False,
        "deleted": False,
        "updatedAt": time,
        "createdAt": time
    }
    try:
        responce = collection.insert_one(signup_form) 
    except Exception as err:
        print(
            {"status": False,
                "section": 3, 
                "message": err})
        raise mssg
    signup_form.update({'id': str(responce.inserted_id)}) 
    return signup_form

if __name__ == "__main__":
    ...