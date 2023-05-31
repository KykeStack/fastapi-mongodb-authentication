import secrets
from typing import Any, Dict, List, Optional, Union
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, HttpUrl, PostgresDsn, validator
# from dotenv import dotenv_values

# secrets=dotenv_values(".env.local")

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str
    SECRET_KEY: str
    TOTP_SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_ALGORITHM: str 
    TOTP_ALGORITHM: str
    SERVER_NAME: str 
    DATABASE_NAME: str
    MONGODB_URL: str 
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    
    EMAILS_ENABLED: bool = False

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    class Config:
        env_file = ".env.local"

settings = Settings()
