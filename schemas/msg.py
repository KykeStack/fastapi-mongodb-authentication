from pydantic import BaseModel


class Msg(BaseModel):
    msg: str

if __name__ == "__main__":
    ...