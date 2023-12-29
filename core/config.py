from typing import List, Optional, Union
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, HttpUrl, validator

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str
    SECRET_KEY: str
    TOTP_SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int 
    REFRESH_TOKEN_EXPIRE_MINUTES: int 
    JWT_ALGORITHM: str 
    TOTP_ALGORITHM: str
    DATABASE_NAME: str
    MONGODB_URL: str 
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    
    # For email management is necessary, an SMTP host 
    EMAILS_ENABLED: bool = False
    
    #Contact/Support Email
    EMAILS_TO_EMAIL: Optional[EmailStr] = None
    EMAILS_FROM_NAME: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_TLS: bool = False
    SMTP_SSL: bool = True
    SMTP_USER: Optional[EmailStr] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAIL_TEMPLATES_DIR: Optional[str] = None
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: Optional[int] = 1
    
    # Add common template environment elements
    SERVER_HOST: Optional[HttpUrl] = None #this is the enpoint 
    SERVER_BOT: Optional[str] = None #Contact bot 
    SERVER_NAME: Optional[str] = None # email domain

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    class Config:
        env_file = "./.env"

settings = Settings()

if __name__ == "__main__":
    ...
