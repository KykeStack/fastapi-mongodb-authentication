from pydantic import BaseModel, EmailStr, validator, Field
from typing import Annotated, Optional
from enum import Enum

from localData.Countries import COUNTRIES
from datetime import datetime

import phonenumbers

def validate_names(name):
    if len(name) > 25:
        raise ValueError(f"Invalid Length of name {name}")
    validate_name = name.capitalize()
    return validate_name

def validate_country(country):
    try:
        if country in COUNTRIES:
            index : int = COUNTRIES.index(country)
            return COUNTRIES[index]
        else:
            raise ValueError(f"Country name: {country}, not Found")
    except Exception as e:
        raise e
    
def validate_birthdate(date):
        valid_formats : list[str] = [
            '%d/%m/%Y', '%d-%m-%Y', '%Y/%d/%m', '%Y-%d-%m', '%d %B, %Y']
        for format in valid_formats:
            try:
                return str(datetime.strptime(date, format).date())
            except Exception:
                pass
        raise ValueError(f"Invalid birthdate: {date}. List of valid formats:{valid_formats}")
    
def validate_phonenumber(phonenumber):
    if phonenumber is not None:
        try:
            parsed = phonenumbers.parse(phonenumber)
            if phonenumbers.is_valid_number(parsed):
                joined_phonenumber = phonenumber.replace(" ", "")
                return joined_phonenumber
            else:
                raise ValueError(f"Invalid phone number: {phonenumber}")
        except Exception as e:
            raise ValueError(e)
    
def validate_username(username):
    assert username.isalnum(), 'must be alphanumeric'
    validate_username = username.capitalize()
    return validate_username


class Gender(str, Enum):
    not_given = 'not_given'
    male = 'male'
    female = 'female'
    other = 'other'

class FullName(BaseModel):
    name: str
    secondName: Optional[str] = None
    surname: str
    secondSurname: Optional[str] = None
    
    @validator("name")
    def lower_name(cls, value):
        validate_names(value)
        
    @validator("secondName")
    def lower_secondName(cls, value):
        validate_names(value)

    @validator("surname")
    def lower_surname(cls, value: str):
        validate_names(value)

    @validator("secondSurname")
    def lower_secondSurname(cls, value: str):
        validate_names(value)


class OptionalFullName(FullName):
    name: Optional[str]
    secondName: Optional[str]
    surname: Optional[str]
    secondSurname: Optional[str]


class UserIn(BaseModel):
    id: str
    username: str
    email: EmailStr
    password: Optional[str] = None 
    fullName: Optional[FullName] = None 
    birthdate: Optional[str] = None
    gender: Optional[str] = None
    country: Optional[str] = None
    phoneNumber: Optional[str] = None
    userExperience: Optional[bool] = True


class UserOut(BaseModel):
    id: str
    email: Optional[str] = None 
    fullName: Optional[FullName] = None 
    username: Optional[str] = None 
    birthdate: Optional[str] = None 
    gender: Optional[Gender] = None
    country: Optional[str] = None 
    phoneNumber: Optional[str] = None 
    userExperience: Optional[bool] = None
    createdAt: datetime
    updatedAt: datetime
    emailValidated: Optional[bool] = None
    totpSecret: Optional[bool] = None
    
    
class SignUpFormIn(BaseModel):
    email: EmailStr
    password: Annotated[ 
        str,
        Field(regex= "((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})")]
    fullName: Optional[FullName] = None
    username: str
    birthdate: Optional[str] = None
    gender: Optional[Gender] = None
    country: Optional[str] = None
    phoneNumber: Optional[str] = None 
    userExperience: Optional[bool]

    @validator("country")
    def parse_country(cls, value):
        validate_country(value)

    @validator("phoneNumber")
    def parse_phone_number(cls, value):
        validate_phonenumber(value)
    
    @validator("birthdate")
    def parse_birthdate(cls, value):
        validate_birthdate(value)
    
    @validator('username')
    def username_alphanumeric(cls, value):
        validate_username(value)

class SignUpFormOut(BaseModel):  
    id: Optional[str] = None
    username: str
    email: EmailStr
    fullName: Optional[FullName] = None 
    birthdate: Optional[str] = None
    gender: Optional[str] = None
    country: Optional[str] = None
    phoneNumber: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime


class UpdateUserName(FullName):
    name: Optional[str] = None 
    secondName: Optional[str] = None 
    surname: Optional[str] = None 
    secondSurname:Optional[str] = None 


class UpdateUserData(BaseModel):
    email: Optional[str] = None 
    fullName: Optional[UpdateUserName] = None 
    username: Optional[str] = None 
    birthdate: Optional[str] = None 
    gender: Optional[Gender] = None 
    country: Optional[str] = None 
    phoneNumber: Optional[str] = None 
    userExperience: Optional[bool]  = None 
    
    @validator("country")
    def parse_country(cls, value):
        validate_country(value)
         
    @validator("phoneNumber")
    def parse_phone_number(cls, value):
        validate_phonenumber(value)
    
    @validator("birthdate")
    def parse_birthdate(cls, value):
        validate_birthdate(value)
    
    @validator('username')
    def username_alphanumeric(cls, value):
        validate_username(value)
        
if __name__ == "__main__":
    ...
