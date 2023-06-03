from fastapi import APIRouter
from api.api_v1.endpoints import (
    validate,
    signin,
    signup,
    login,
    services, 
    proxy
)

api_router = APIRouter()
api_router.include_router(login.router, prefix="/login", tags=["Login"])

api_router.include_router(proxy.router, prefix="/proxy", tags=["proxy"])
api_router.include_router(services.router, prefix="/service", tags=["service"])

api_router.include_router(validate.router, prefix="/validate", tags=["validate"])
api_router.include_router(signin.router, prefix="/signin", tags=["Signin"])
api_router.include_router(signup.router, prefix = "/signup", tags = ["Signup"])

