from pydantic import BaseModel

class MagicLink(BaseModel):
    exp: str 
    sub: str
    fingerprint: str
    
if __name__ == "__main__":
    ...