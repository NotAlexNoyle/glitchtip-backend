"""AWS ElastiCache IAM authentication for the Valkey cache and task broker.

ElastiCache can authenticate a connection with a short-lived IAM auth token
instead of a stored ACL password, which removes the cache password from the
deployment entirely. The token is a SigV4-presigned string that **expires 15
minutes** after it is minted, so it cannot be read once into ``CACHES`` at
startup: Valkey only checks the password at ``AUTH``/``HELLO``, so connections
already open survive expiry, but the driver opens new ones on its own schedule
— reconnect after a failover, an idle socket reaped by a load balancer, the
blocking-connection pool growing for django-vtasks — and those fail to
authenticate once the token is stale. ElastiCache goes further and
**disconnects an IAM-authenticated connection after 12 hours** unless a fresh
``AUTH`` has been sent on it.

django-vcache exists for exactly this: it keeps a credential current for every
live connection and mints through ``OPTIONS["credential_provider"]``. The
minting itself is the driver's ``django_vcache.contrib.aws`` provider; what
lives here is the *policy* — whether IAM auth is on, and what TLS we insist on
before letting a live credential onto the wire.

Enable with ``VALKEY_IAM_AUTH=true``; see ``glitchtip/settings.py``.

One driver serves both consumers. django-vtasks' broker reaches Valkey through
``cache.get_raw_client()`` on the ``default`` cache alias, so the broker
authenticates with the same rotating credential as the cache and needs no
configuration of its own.

The token signs the **cache name** and **user id**, neither of which is the
hostname, so unlike the RDS case the provider cannot always work them out from
the endpoint. It derives them from serverless, ``clustercfg.`` and
``master.``/``replica.`` endpoint shapes; a node endpoint or a CNAME needs
``VALKEY_IAM_CACHE_NAME`` and ``VALKEY_IAM_REGION``. The IAM-enabled user goes
in the URL userinfo — ``valkeys://<iam-user>@host:6379/0``, no password —
because that is the ACL user the token is signed for.

Outside GlitchTip, ElastiCache IAM auth also requires:

* Valkey 7.2+ or Redis OSS 7+ with **in-transit encryption enabled**;
* an ElastiCache user with authentication mode ``iam`` whose **user id equals
  its user name**, in a **user group attached to the cache**;
* an IAM policy granting ``elasticache:Connect`` on both the cache ARN and the
  user ARN;
* TLS, which is enforced below — a token travels as a cleartext ``AUTH``
  argument.

See ``docs/ai/elasticache_iam_aws_setup.md`` for the AWS-side setup.
"""

from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

#: The driver's own ElastiCache provider. It reads the renewal deadline out of
#: the token and derives cache name, region and serverless-ness from the
#: endpoint when the hostname's shape allows, so none of that is configuration
#: here. botocore is already a transitive dependency of GlitchTip, so
#: django-vcache's ``[aws]`` extra adds nothing we do not already have.
ELASTICACHE_IAM_PROVIDER = "django_vcache.contrib.aws.elasticache_iam_token"

#: LOCATION schemes that encrypt the connection outright.
TLS_SCHEMES = ("valkeys", "rediss")

#: Encrypted only when a CA bundle is configured: with ``sentinel://`` the
#: master connection is TLS exactly when ``ssl_ca_certs`` is set.
CONDITIONAL_TLS_SCHEMES = ("sentinel",)


def _scheme(location):
    return urlsplit(location).scheme.lower() if location else ""


def configure_options(
    options,
    *,
    location,
    iam_auth,
    credential_provider=None,
    provider_options=None,
    credential_ttl=None,
    allow_unverified_tls=False,
):
    """Apply rotating-credential settings to the cache alias's ``OPTIONS``.

    Mutates and returns ``options``, but only after every check has passed —
    a caller that catches ``ImproperlyConfigured`` is never left with a
    provider half-wired onto a plaintext LOCATION.

    ``iam_auth`` selects the shipped AWS provider; ``credential_provider`` is
    the generic hook for any other issuer (Vault, Azure Entra ID, an in-house
    signer). They are mutually exclusive: one alias has one credential source,
    and silently preferring one over the other would mean an operator who set
    both gets an authentication scheme they did not choose.

    ``credential_provider``, ``credential_provider_options`` and
    ``credential_ttl`` already present in ``options`` are overwritten rather
    than honoured, the same way ``db_iam`` treats ``credential_provider``:
    once IAM auth is on it owns the credential source, and an override left
    behind in a ``CACHES`` dict would quietly win over the environment.

    Kept here rather than inline in settings so the guards are reachable from
    tests without re-importing settings.
    """
    if not iam_auth and not credential_provider:
        return options

    if iam_auth and credential_provider:
        raise ImproperlyConfigured(
            "VALKEY_IAM_AUTH and VALKEY_CREDENTIAL_PROVIDER are mutually "
            "exclusive: VALKEY_IAM_AUTH already selects "
            f"{ELASTICACHE_IAM_PROVIDER}. Set VALKEY_CREDENTIAL_PROVIDER only "
            "for a non-AWS credential issuer, and leave VALKEY_IAM_AUTH off "
            "when you do."
        )

    setting = "VALKEY_IAM_AUTH" if iam_auth else "VALKEY_CREDENTIAL_PROVIDER"

    # A minted credential reaches Valkey as a cleartext AUTH argument — that
    # is how ElastiCache IAM auth works, and why AWS requires in-transit
    # encryption for it. Anyone who can read the connection reads a live,
    # replayable credential. django-vcache offers
    # credential_provider_allow_plaintext as a local-development escape;
    # GlitchTip deliberately does not expose it, because there is no
    # deployment in which shipping a live credential in the clear is the
    # right answer.
    scheme = _scheme(location)
    tls = scheme in TLS_SCHEMES or (
        scheme in CONDITIONAL_TLS_SCHEMES and options.get("ssl_ca_certs")
    )
    if not tls:
        raise ImproperlyConfigured(
            f"{setting} sends the minted credential to Valkey as a cleartext "
            f"AUTH argument, so it requires TLS, but VALKEY_URL uses the "
            f"scheme {scheme or '<none>'!r}. Use a valkeys:// or rediss:// URL — "
            "ElastiCache IAM auth requires in-transit encryption anyway — or, "
            "with sentinel://, set VALKEY_SSL_CA_CERTS."
        )

    # ssl_cert_reqs=none encrypts but authenticates nothing: no certificate
    # chain and no hostname. A live token would then be handed to whatever
    # answers on the cache hostname (split-horizon DNS, a reclaimed CNAME, a
    # compromised sidecar) and could be replayed against the real cache for
    # 15 minutes. Reachable only by deliberately setting
    # VALKEY_IAM_ALLOW_UNVERIFIED_TLS, never by following an error message.
    cert_reqs = options.get("ssl_cert_reqs")
    if (
        isinstance(cert_reqs, str)
        and cert_reqs.strip().lower() == "none"
        and not allow_unverified_tls
    ):
        raise ImproperlyConfigured(
            f"VALKEY_SSL_CERT_REQS='none' cannot be combined with {setting}: "
            "it encrypts the connection but verifies nothing about the "
            "server, so a live credential would be handed to whatever answers "
            "on the cache hostname and could be replayed against the real "
            "cache. Drop VALKEY_SSL_CERT_REQS and set VALKEY_SSL_CA_CERTS if "
            "the cache uses a private CA. If you genuinely accept an "
            "unauthenticated server, set VALKEY_IAM_ALLOW_UNVERIFIED_TLS=true."
        )

    if iam_auth and not urlsplit(location).username:
        # The token signs a user id, and AWS requires an IAM-mode user's id to
        # equal its user name — so the ACL user in the userinfo is what gets
        # signed. Without it the provider raises at connect time, on the
        # first cache operation, rather than at startup.
        raise ImproperlyConfigured(
            "VALKEY_IAM_AUTH needs the IAM-enabled ElastiCache user in the "
            "VALKEY_URL userinfo, because that is the ACL user the token is "
            "signed for: valkeys://<iam-user>@host:6379/0 (no password — the "
            "token replaces it)."
        )

    resolved = dict(options)
    resolved["credential_provider"] = (
        ELASTICACHE_IAM_PROVIDER if iam_auth else credential_provider
    )
    if provider_options:
        resolved["credential_provider_options"] = dict(provider_options)
    if credential_ttl:
        # Only a fallback: the ElastiCache provider states the token's own
        # expiry, which the driver prefers, so this is unused with it.
        resolved["credential_ttl"] = credential_ttl

    options.clear()
    options.update(resolved)
    return options
