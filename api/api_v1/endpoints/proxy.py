from typing import Any
from pydantic import AnyHttpUrl
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
import httpx

from functionTypes.common import FunctionStatus
from api.deps import get_current_active_user

UNAUTHORIZED_MESSAGE = HTTPException(status_code=401, detail="Could not Validate Credentials")

router = APIRouter()

"""
A proxy for the frontend client when hitting cors issues with axios requests. Adjust as required. This version has
a user-login dependency to reduce the risk of leaking the server as a random proxy.
"""

@router.post("/{path:path}")
async def proxy_post_request(
    *, path: AnyHttpUrl, request: Request, current_user: FunctionStatus = Depends(get_current_active_user),
) -> Any:
    # https://www.starlette.io/requests/
    # https://www.python-httpx.org/quickstart/
    # https://github.com/tiangolo/fastapi/issues/1788#issuecomment-698698884
    # https://fastapi.tiangolo.com/tutorial/path-params/#__code_13
    if not current_user.status:
        raise 
    try:
        data = await request.json()
        async with httpx.AsyncClient() as client:
            proxy = await client.post(f"{path}", 
                headers={
                    "Content-Type": request.headers.get("Content-Type"),
                    "Authorization": request.headers.get("Authorization"),
                }, 
                data=data)
        return Response(content=proxy.content, status_code=proxy.status_code)
    except Exception as e:
        raise UNAUTHORIZED_MESSAGE


@router.get("/{path:path}")
async def proxy_get_request(
    *, path: AnyHttpUrl, request: Request, current_user: FunctionStatus = Depends(get_current_active_user),
) -> Any:
    if not current_user.status:
        raise UNAUTHORIZED_MESSAGE
    
    try:
        async with httpx.AsyncClient() as client:
                    proxy = await client.get(f"{path}", 
                        headers= {
                            "Content-Type": request.headers.get("Content-Type", "application/x-www-form-urlencoded"),
                            "Authorization": request.headers.get("Authorization"),
                        })
        return Response(content=proxy.content, status_code=proxy.status_code)
    except Exception as e:
        raise UNAUTHORIZED_MESSAGE

if __name__ == "__main__":
    ...
