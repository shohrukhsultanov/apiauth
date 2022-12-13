import base64
import hashlib
import hmac
import os

from fastapi import Header, HTTPException, Request, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseSettings
from starlette.status import HTTP_403_FORBIDDEN


class Settings(BaseSettings):
    api_secret: str = os.getenv('API_SECRET')
    url_path: str = os.getenv('URL_PATH')
    api_key: str = os.getenv('API_KEY')

    class Config:
        env_file = './lib/configs.env'


settings = Settings()


def sign(api_secret: str, accept: str, content_type: str, url_path: str):
    api_secret = api_secret
    text_to_sign = accept + content_type + url_path
    signature = hmac.new(
        api_secret.encode('utf-8'),
        text_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature = base64.b64encode(signature)
    signature = signature.decode('utf-8')
    return signature


api_key_header = APIKeyHeader(name="x-request-api", auto_error=False)


async def get_api_key(request: Request, x_request_signature: str = Header(default=None),
                      api_key_header: str = Security(api_key_header)):
    api_secret = settings.api_secret
    accept = str(request.headers.get("accept"))
    content_type = str(request.headers.get("content-type"))
    url_path = settings.url_path

    signature = sign(api_secret, accept, content_type, url_path)

    if hmac.compare_digest(signature, x_request_signature) and api_key_header == settings.api_key:
        return api_key_header
    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate API KEY"
        )
