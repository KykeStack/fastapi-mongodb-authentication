from fastapi import APIRouter
from api.api_v1.endpoints import (
    signin,
    signup
)
# from api.api_v1.endpoints import (
#     login,
#     users,
#     proxy,
#     services,
# )

api_router = APIRouter()
# api_router.include_router(login.router, prefix="/login", tags=["login"])
# api_router.include_router(users.router, prefix="/users", tags=["users"])
# api_router.include_router(proxy.router, prefix="/proxy", tags=["proxy"])
# api_router.include_router(services.router, prefix="/service", tags=["service"])

# api_router.include_router(plans.router, prefix="/plans", tags=["Plans"])
# api_router.include_router(purchases.router, prefix="/purchase", tags=["Purchase"])
api_router.include_router(signin.router, prefix="/signin", tags=["Signin"])
api_router.include_router(signup.router, prefix = "/signup", tags = ["Signup"])

