from typing import Any, Optional
from pydantic import BaseModel

class FunctionStatus(BaseModel):
    functionName: Optional[str] = None
    status: bool
    section: Optional[int] 
    message: Optional[Any] = None
    content: Optional[Any] = None
    metadata: Optional[Any] = None
    error: Optional[Any] = None
    
if __name__ == "__main__":
    ...