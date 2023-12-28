from email_validator import  EmailNotValidError, validate_email 
from pydantic import BaseModel, EmailStr, validator, ValidationError

from typing import Optional
from schemas.user import UserOut

def email_validation(email: str) -> Optional[str]:
    try:
        email_object = validate_email(email.lower())
        return email_object.email
    except EmailNotValidError as error:
        raise ValidationError(error)

class EmailContent(BaseModel):
    email: EmailStr
    subject: str
    content: str
    
    @validator("email")
    def email_in(cls, value):
        return email_validation(value)

class EmailValidation(BaseModel):
    email: EmailStr
    subject: str
    token: str
    
    @validator("email")
    def email_in(cls, value):
        return email_validation(value)

class UserAndEmai(BaseModel):
    userUpdated: UserOut
    claim: str
        
if __name__ == "__main__":
    ...