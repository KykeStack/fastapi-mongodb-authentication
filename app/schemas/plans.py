from pydantic import BaseModel
from typing import Optional
from enum import Enum
    
class Purchase(str, Enum):
    standard = 'standard'
    premium = 'premium'

class SinglePurchase(BaseModel):
    id: Optional[str] = None
    userId: str
    username: str
    purchase: str
    type: str
    price: float
    
class Period(str, Enum):
    monthly = 'monthly'
    biannual = "biannual"
    annual = "annual"

class PlansIn(BaseModel):
    type: Purchase
    period: Period

class PlansOut(BaseModel):  
    userId: str
    username: str
    planType: str
    period: str
    price: float


if __name__ == "__main__":
    ...