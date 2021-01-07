import datetime
import logging
import time
from typing import Dict, List, Optional
import uuid

from chalice import ForbiddenError
from jose import JWTError, jwk, jws, jwt
import pydantic

_logger = None
ALGORITHMS = {'RS256', 'RS384', 'RS512'}
AUDIENCE = 'Admin'
LOG_LEVEL = logging.INFO
TOKEN_LIFETIME_SECONDS = 60 * 60 * 24


def logger():
    global _logger
    if not _logger:
        logging.basicConfig()
        _logger = logging.getLogger(__name__)
        _logger.setLevel(LOG_LEVEL)
    return _logger


class LoginCredentials(pydantic.BaseModel):
    user_email: str
    password: str


def make_jwks() -> Dict[str, List[Dict]]:
    """
    gets the jwks from the keypair
    :return: JWK keyset
    """

    global _keyset
    x = get_public_key_bytes()
    keys = {'keys': []}
    for alg in ALGORITHMS:
        jwkey = jwk.construct(x, alg).to_dict()
        jwkey['use'] = 'sig'
        jwkey['kid'] = str(uuid.uuid4())
        keys['keys'].append(jwkey)
    _keyset = keys
    return _keyset


def sign(
        algorithm: str = 'RS256',
        claims: Optional[Dict] = None,
        expires_delta: Optional[datetime.timedelta] = None
) -> str:
    """
    Create a signed access token with claims
    :param algorithm: the RSA algorithm to use - can be RS256, RS384, RS512
    :param claims: the claims to put in the key
    :param expires_delta: how long the token is good for
    :return: a JWT string
    """

    if algorithm not in ALGORITHMS:
        raise ValueError(f'Unsupported Algorithm {algorithm}')

    if claims is None:
        claims = dict()

    if not set(claims).isdisjoint({'iat', 'exp'}):
        # I don't want the caller to deliver the issued at time nor the expiration for security
        raise ValueError('Invalid claims')

    issued = time.time()
    claims_to_encode = claims.copy()
    if expires_delta:
        expire = issued + expires_delta.total_seconds()
    else:
        expire = issued + TOKEN_LIFETIME_SECONDS

    claims_to_encode['iat'] = issued
    claims_to_encode['exp'] = expire

    # TODO: see if it makes more sense to use the same types that python-jose uses instead of a string here.
    encoded = jws.sign(claims_to_encode, get_private_key_str(), algorithm=algorithm)
    return encoded


def validate(jw_token: str) -> dict:
    """
    Verifies the token's signature and delivers the claims if the token is valid.
    :param jw_token: the bearer token string
    :return: dict of claims
    :raises HTTPException if there are issues with the tokens or claims
    """

    try:
        header = jwt.get_unverified_header(jw_token)
    except JWTError as e:
        raise ForbiddenError('Invalid Header') from e

    if header['alg'] not in ALGORITHMS:
        raise ForbiddenError('Unsupported "alg"')

    try:
        claims = jwt.decode(jw_token, make_jwks(), header['alg'], audience=AUDIENCE)
    except JWTError as e:
        logger().error("JWT decode error", exc_info=e)
        raise ForbiddenError('Invalid claims or signature') from e

    return claims

