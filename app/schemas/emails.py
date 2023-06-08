from email_validator import  EmailNotValidError, validate_email 
from pydantic import BaseModel, EmailStr, validator
from schemas.user import UserOut

def email_validation(email):
    valid_email_format = email.lower()
    try:
        email_object = validate_email(valid_email_format)
        return email_object.email
    except EmailNotValidError as errorMsg:
        raise errorMsg

    
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