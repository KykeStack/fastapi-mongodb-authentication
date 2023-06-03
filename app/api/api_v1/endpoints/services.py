from typing import Any

from fastapi import APIRouter

from schemas.msg import Msg
from schemas.emails import EmailContent
from utils.emailsMessage import send_web_contact_email

router = APIRouter()

@router.post("/contact", response_model=Msg, status_code=201)
def send_email(*, data: EmailContent) -> Any:
    """
    Standard app contact us.
    """
    send_web_contact_email(data=data)
    return {"msg": "Web contact email sent"}
