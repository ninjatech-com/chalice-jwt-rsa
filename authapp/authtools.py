import pydantic
from jose import jwt, jwk


class LoginCredentials(pydantic.BaseModel):
    user_email: str
    password: str


def make_jwks():
    ...


def sign():
    ...


def validate():
    ...

