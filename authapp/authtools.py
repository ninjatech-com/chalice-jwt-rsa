from base64 import urlsafe_b64encode, urlsafe_b64decode
import datetime
import logging
import os
import time
from typing import Dict, List, Optional
import uuid

from chalice import ForbiddenError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwk, jws, jwt

ALGORITHMS = {'RS256', 'RS384', 'RS512'}
AUDIENCE = 'Admin'
LOG_LEVEL = logging.INFO
TOKEN_LIFETIME_SECONDS = 60 * 60 * 24
_logger = None
_private_key = None


def logger() -> logging.Logger:
    global _logger
    if not _logger:
        logging.basicConfig()
        _logger = logging.getLogger(__name__)
        _logger.setLevel(LOG_LEVEL)
    return _logger


def private_key() -> rsa.RSAPrivateKey:
    global _private_key
    if not _private_key:
        _private_key = serialization.load_pem_private_key(
            urlsafe_b64decode(os.environ['JWT_PRIVATE_KEY']), password=None)
    return _private_key


def private_key_str() -> str:
    pk = private_key()

    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


def public_key() -> bytes:
    pk = private_key()
    pubkey = pk.public_key()
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def make_jwks() -> Dict[str, List[Dict]]:
    """
    gets the jwks from the keypair
    :return: JWK keyset
    """

    global _keyset
    x = public_key()
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
    encoded = jws.sign(claims_to_encode, private_key_str(), algorithm=algorithm)
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

