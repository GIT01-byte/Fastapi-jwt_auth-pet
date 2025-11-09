from pydantic import BaseModel


class EmpoloyeeScheme(BaseModel):
    id: int
    name: str
    last_name: str
    phone: int
    image_url: str


class EmpoloyeeAddScheme(EmpoloyeeScheme):
    pass

