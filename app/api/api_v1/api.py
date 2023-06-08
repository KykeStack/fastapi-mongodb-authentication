from fastapi import APIRouter
from api.api_v1.endpoints.internal import admin
from api.api_v1.endpoints import (
    signin,
    signup,
    login,
    logout,
    delete,
    services, 
    proxy
)


api_router = APIRouter()
api_router.include_router(login.router, prefix="/login", tags=["Login"])
api_router.include_router(logout.router, prefix="/logout", tags=["Logout"])

api_router.include_router(proxy.router, prefix="/proxy", tags=["Proxy"])
api_router.include_router(services.router, prefix="/service", tags=["Service"])

api_router.include_router(delete.router, prefix="/delete", tags=["Delete"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin"])

api_router.include_router(signin.router, prefix="/signin", tags=["Signin"])
api_router.include_router(signup.router, prefix = "/signup", tags = ["Signup"])

if __name__ == "__main__":
    ...
