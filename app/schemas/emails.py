from email_validator import  EmailNotValidError, validate_email 
from pydantic import BaseModel, EmailStr, validator
    
class EmailContent(BaseModel):
    email: EmailStr
    subject: str
    content: str
    
    @validator("email")
    def validate_email(cls, value: str):
        valid_email_format = value.lower()
        try:
            email_object = validate_email(valid_email_format)
            return email_object.email
        except EmailNotValidError as errorMsg:
            raise errorMsg
        

class EmailValidation(BaseModel):
    email: EmailStr
    subject: str
    token: str
    
    @validator("email")
    def validate_email(cls, value: str):
        valid_email_format = value.lower()
        try:
            email_object = validate_email(valid_email_format)
            return email_object.email
        except EmailNotValidError as errorMsg:
            raise errorMsg
        
