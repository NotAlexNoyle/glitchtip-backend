import json
import time
from urllib.parse import urlencode, urlsplit

from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.cache import cache
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.views.decorators.http import require_http_methods

from apps.api_tokens.models import generate_token

from .provider import AUTH_CODE_LIFETIME, _grant_cache_key

SIGNED_DATA_MAX_AGE = 600  # 10 minutes


@login_required
@require_http_methods(["GET", "POST"])
async def oauth_consent(request):
    try:
        data = signing.loads(request.GET.get("data", ""), max_age=SIGNED_DATA_MAX_AGE)
    except (signing.BadSignature, signing.SignatureExpired):
        return HttpResponseBadRequest("Invalid or expired authorization request.")

    redirect_uri = data["redirect_uri"]
    if request.method == "GET":
        return TemplateResponse(
            request,
            "oauth/consent.html",
            {
                "client_name": data.get("client_name") or "",
                "client_id": data.get("client_id", ""),
                "redirect_host": urlsplit(redirect_uri).netloc,
                "scopes": data.get("scopes") or [],
                "signed_data": request.GET["data"],
            },
        )

    if "deny" in request.POST:
        return _redirect_to_client(
            redirect_uri, {"error": "access_denied"}, data.get("state")
        )

    user = await request.auser()
    code = generate_token()
    now = int(time.time())
    grant_data = json.dumps(
        {
            "client_id": data["client_id"],
            "user_id": user.id,
            "scopes": data.get("scopes") or [],
            "expires_at": now + AUTH_CODE_LIFETIME,
            "code_challenge": data["code_challenge"],
            "redirect_uri": data["redirect_uri"],
            "redirect_uri_provided_explicitly": data[
                "redirect_uri_provided_explicitly"
            ],
            "resource": data.get("resource"),
        }
    )
    await cache.aset(_grant_cache_key(code), grant_data, AUTH_CODE_LIFETIME)

    return _redirect_to_client(redirect_uri, {"code": code}, data.get("state"))


def _redirect_to_client(redirect_uri: str, params: dict, state: str | None):
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return HttpResponseRedirect(f"{redirect_uri}{separator}{urlencode(params)}")
