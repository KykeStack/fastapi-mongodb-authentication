from pydantic import BaseModel, EmailStr, validator, Field
from typing import Annotated, Optional
from enum import Enum

from localData.Countries import COUNTRIES
from datetime import datetime

import phonenumbers
    
class Gender(str, Enum):
    not_given = 'not_given'
    male = 'male'
    female = 'female'
    other = 'other'

"""
This class defines a model for a full name with four attributes: 
- name, second_name, surname, and second_surname. 

The Annotated function is used to specify the types and validation rules for each attribute, 
with additional metadata such as a title and description. The name and surname attributes are 
required strings, while second_name and second_surname are optional strings. All attributes 
have a maximum length of 25 characters and a minimum length of 2. 

This class inherits from BaseModel and has a configuration that sets its title to "Full Name".
"""

class FullName(BaseModel):
    name: Annotated[str, Field(
        title = "User first name",
        description = "Required field",
        max_length = 25, 
        min_length = 2)]  
     
    secondName: Annotated[Optional[str], Field(
        title = "User second name",
        description = "Optional field",
        max_length = 25,
        min_length=2)] = None
    
    surname: Annotated[str, Field(
        title = "User first surname",
        description = "Required field",
        max_length = 25,
        min_length = 2)]  
    
    secondSurname: Annotated[Optional[str], Field(
        title = "User second surname",
        description = "Optional field",
        max_length=25, 
        min_length=2)] = None
        
    @validator("name")
    def lower_name(cls, value: str):
        validate_name = value.lower().capitalize()
        return validate_name
    
    @validator("secondName")
    def lower_secondName(cls, value: str):
        if value is not None:
            validate_secondName = value.lower().capitalize()
            return validate_secondName

    @validator("surname")
    def lower_surname(cls, value: str):
        validate_surname = value.lower().capitalize()
        return validate_surname

    @validator("secondSurname")
    def lower_secondSurname(cls, value: str):
        if value is not None:
            validate_secondSurname = value.lower().capitalize()
            return validate_secondSurname

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
    fullName: FullName
    birthdate: str
    gender: str
    country: str
    phoneNumber: Optional[str] = None
    userExperience: Optional[bool] = True


class UserOut(BaseModel):
    id: str
    email: Optional[str] = None 
    fullName: Optional[OptionalFullName] = None 
    username: Optional[str] = None 
    birthdate: Optional[str] = None 
    gender: Optional[Gender]
    country: Optional[str] = None 
    phoneNumber: Optional[str] = None 
    userExperience: Optional[bool] = None
    createdAt: datetime
    updatedAt: datetime

"""
This class is a model for a sign-up form with 7 required attributes: 
-email, password, name, birthdate, country, phone_number, and privacy_policy. 

It also has an optional attributes:
- user_experience. 
The password, country, phone_number, and birthdate attributes have custom 
validators that ensure they meet specific criteria. 
The name attribute is an instance of another class called fullName. 
This class inherits from BaseModel and has a configuration that sets its title to "Sing Up form".
"""

class SignUpFormIn(BaseModel):
    email: EmailStr
    password: Annotated[ 
        str,
        Field(regex= "((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})")]
    fullName: FullName
    username: str
    birthdate: Annotated[str, Field(max_length=25)] 
    gender: Gender
    country: Annotated[str, Field(max_length=25)] 
    phoneNumber: Optional[str] = None 
    privacyPolicy: Optional[bool] = True
    userExperience: Optional[bool]

    @validator("country")
    def parse_country(cls, value):
         try:
            if value in COUNTRIES:
                index : int = COUNTRIES.index(value)
                return COUNTRIES[index]
            else:
                raise ValueError(f"Country name: {value}, not Found")
         except Exception as e:
             raise e
         
    @validator("phoneNumber")
    def parse_phone_number(cls, value):
        if value is not None:
            try:
                parsed = phonenumbers.parse(value)
                if phonenumbers.is_valid_number(parsed):
                    joined_phonenumber = value.replace(" ", "")
                    return joined_phonenumber
                else:
                    raise ValueError(f"Invalid phone number: {value}")
            except Exception as e:
                raise ValueError(e)
    
    @validator("birthdate")
    def parse_birthdate(cls, value):
        date = value
        valid_formats : list[str] = [
            '%d/%m/%Y', '%d-%m-%Y', '%Y/%d/%m', '%Y-%d-%m', '%d %B, %Y']
        for format in valid_formats:
            try:
                return str(datetime.strptime(date, format).date())
            except Exception:
                pass
        raise ValueError(f"Invalid birthdate: {value}. List of valid formats:{valid_formats}")
    
    @validator('username')
    def username_alphanumeric(cls, value):
        assert value.isalnum(), 'must be alphanumeric'
        validate_username = value.lower()
        return validate_username


class SignUpFormOut(BaseModel):  
    id: Optional[str] = None
    username: str
    email: EmailStr
    fullName: FullName
    birthdate: str
    gender: str
    country: str
    phoneNumber: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime


class UpdateUserName(FullName):
    name: Optional[str] = None 
    secondName: Optional[str] = None 
    surname: Optional[str] = None 
    secondSurname:Optional[str] = None 


class UpdateUserData(SignUpFormIn):
    email: Optional[str] = None 
    fullName: Optional[UpdateUserName] = None 
    username: Optional[str] = None 
    birthdate: Optional[str] = None 
    gender: Optional[Gender] = None 
    country: Optional[str] = None 
    phoneNumber: Optional[str] = None 
    privacyPolicy: Optional[bool] = None
    userExperience: Optional[bool]  = None 


if __name__ == "__main__":
    ...
