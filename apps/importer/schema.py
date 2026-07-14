from pydantic import HttpUrl

from glitchtip.schema import CamelSchema


class ImportIn(CamelSchema):
    url: HttpUrl
    auth_token: str
