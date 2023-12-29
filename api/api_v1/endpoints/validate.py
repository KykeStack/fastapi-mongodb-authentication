from fastapi import APIRouter, HTTPException, Depends
from typing import Union, Optional
import aiohttp
import asyncio

from core.config import settings
from dataBase.client import session

from pymongo.collection import Collection
from pymongo.database import Database
from bson.objectid import ObjectId

from jose import jwt
import json

INVALID_IDENTIFIER = 'Please, check identifier.'
INVALID_JWT = 'Of course! You shall not pass!'

JWT_SECRET =  settings.SECRET_KEY
JWT_ALGORITHM = settings.JWT_ALGORITHM
UNAUTHORIZED_MESSAGE = HTTPException(status_code=401, detail="Could not Validate Credentials")

def magic_get_db() -> Union[Collection, Database]:
    try:
        collection = session['Magic']
        yield collection
    finally:
        session

def password_get_db() -> Union[Collection, Database]:
    try:
        collection = session['Password']
        yield collection
    finally:
        session

router = APIRouter()

async def request(url: str, json_data: dict, headers: dict) -> Union[dict, HTTPException]:
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                url=url, 
                headers=headers, 
                json=json_data
            ) as responce:
                data = await responce.read()
                hashrate = json.loads(data)
        except HTTPException as e:
            raise UNAUTHORIZED_MESSAGE
        return hashrate
        
@router.get('/magic-login', status_code=200)
def validate(magic: str, collection: Collection = Depends(magic_get_db)):
    magic_login_url =  f"{settings.SERVER_HOST}{settings.API_V1_STR}/login/claim"
    
    try:
        payload = jwt.decode(magic, JWT_SECRET, algorithms=[JWT_ALGORITHM])     
        user: dict = collection.find_one({'foreignId': ObjectId(payload.get('sub'))}) 
    except Exception as error:
        raise UNAUTHORIZED_MESSAGE

    if not user:
        raise UNAUTHORIZED_MESSAGE
    
    json_data = {'claim': user.get('claimToken')}
    bearer_token = {'Authorization': f'Bearer {magic}'}

    return asyncio.run(request(url=magic_login_url, json_data=json_data, headers=bearer_token))
    

@router.get('/reset-password', status_code=200)
def validate(token: str, password: Optional[str] = 'password123', collection: Collection = Depends(password_get_db)):
    reset_password_url = f"{settings.SERVER_HOST}{settings.API_V1_STR}/login/reset"  
    try:
        payload = jwt.decode(token=token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM])     
        user: dict = collection.find_one({'foreignId': ObjectId(payload.get('sub'))}) 
    except Exception as error:
        raise UNAUTHORIZED_MESSAGE
    
    if not user:
        raise UNAUTHORIZED_MESSAGE
    
    json_data = {'new_password': password, 'claim': user.get('claimToken')}
    bearer_token = {'Authorization': f'Bearer {token}'}
    return asyncio.run(request(url=reset_password_url, json_data=json_data, headers=bearer_token))