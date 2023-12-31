from fastapi import APIRouter, HTTPException, status, Depends
from typing import Annotated, Any

from functionTypes.common import FunctionStatus
from schemas.msg import Msg

from pymongo.collection import Collection

from crud.user import update_user
from api.deps import get_access_token, get_user_db

router = APIRouter()

mssg = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service Unavailable"
        )

@router.post("/", response_model=Msg)
def revoke_token(
    current_user: Annotated[FunctionStatus, Depends(get_access_token)],
    collection: Collection = Depends(get_user_db)
) -> Any:
    """
    Revoke access token
    """
    if not current_user.status:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=current_user.message,
        )
        
    user = current_user.content
    update_user(
            collection=collection, 
            id=user.get('_id'), 
            data={"accessToken": "", "refreshToken": ""}
        )
    return {"msg": "Token revoked"}

if __name__ == "__main__":
    ...
