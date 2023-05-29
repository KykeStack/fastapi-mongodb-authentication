from email_validator import  EmailNotValidError, validate_email 
from pydantic import BaseModel, EmailStr, validator

class Email(BaseModel):
    email: EmailStr
    
    @validator("email")
    def validate_email(cls, value: str):
        valid_email_format = value.lower()
        try:
            email_object = validate_email(valid_email_format)
            valid_email_format = email_object.email
            return email_object.email
        except EmailNotValidError as errorMsg:
            raise errorMsg
        

class EmailContent(BaseModel):
    email: Email
    subject: str
    content: str


class EmailValidation(BaseModel):
    email: Email
    subject: str
    token: str

