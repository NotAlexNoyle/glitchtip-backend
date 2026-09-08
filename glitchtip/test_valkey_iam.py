"""Tests for GlitchTip's ElastiCache IAM auth policy (``glitchtip.valkey_iam``).

Token minting lives in the driver (``django_vcache.contrib.aws``); what is
tested here is the policy around it — whether IAM auth is wired at all, and
the refusal to configure a live credential onto an unencrypted or unverified
connection.
"""

from unittest import skipUnless

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase
from django.utils.module_loading import import_string

from glitchtip import valkey_iam

TLS_URL = "valkeys://app-iam-user@cache.example.com:6379/0"


class ConfigureOptionsTestCase(SimpleTestCase):
    def test_disabled_leaves_options_untouched(self):
        options = {"DRIVER_CLASS": "gt_rust.valkey.RustValkeyDriver"}
        assert valkey_iam.configure_options(
            options, location="redis://cache:6379/0", iam_auth=False
        ) == {"DRIVER_CLASS": "gt_rust.valkey.RustValkeyDriver"}

    def test_disabled_ignores_the_other_arguments(self):
        # A stray VALKEY_IAM_CACHE_NAME or VALKEY_CREDENTIAL_TTL left in the
        # environment must not switch anything on by itself.
        options = valkey_iam.configure_options(
            {},
            location="redis://cache:6379/0",
            iam_auth=False,
            provider_options={"cache_name": "my-cache"},
            credential_ttl=300,
        )
        assert options == {}

    def test_iam_auth_wires_the_provider(self):
        options = valkey_iam.configure_options({}, location=TLS_URL, iam_auth=True)
        assert options["credential_provider"] == valkey_iam.ELASTICACHE_IAM_PROVIDER

    def test_iam_auth_passes_provider_options(self):
        options = valkey_iam.configure_options(
            {},
            location=TLS_URL,
            iam_auth=True,
            provider_options={"cache_name": "my-cache", "region": "us-east-1"},
        )
        assert options["credential_provider_options"] == {
            "cache_name": "my-cache",
            "region": "us-east-1",
        }

    def test_empty_provider_options_are_not_passed(self):
        # An empty dict would be handed to the provider as conn["options"],
        # which is harmless but noise; more usefully, its absence is what
        # tells a reader that nothing was configured.
        options = valkey_iam.configure_options(
            {}, location=TLS_URL, iam_auth=True, provider_options={}
        )
        assert "credential_provider_options" not in options
        options = valkey_iam.configure_options(
            {}, location=TLS_URL, iam_auth=True, provider_options=None
        )
        assert "credential_provider_options" not in options

    def test_provider_options_are_copied(self):
        # The caller's dict is built from settings and may be reused; the
        # driver keys its registry on these values, so aliasing would let a
        # later mutation silently change an already-configured alias.
        provider_options = {"cache_name": "my-cache"}
        options = valkey_iam.configure_options(
            {}, location=TLS_URL, iam_auth=True, provider_options=provider_options
        )
        provider_options["cache_name"] = "other-cache"
        assert options["credential_provider_options"] == {"cache_name": "my-cache"}

    def test_ttl_is_only_a_fallback(self):
        # The ElastiCache provider states the token's own expiry, which the
        # driver prefers, so this is absent unless explicitly configured.
        assert "credential_ttl" not in valkey_iam.configure_options(
            {}, location=TLS_URL, iam_auth=True
        )
        assert (
            valkey_iam.configure_options(
                {}, location=TLS_URL, iam_auth=True, credential_ttl=300
            )["credential_ttl"]
            == 300
        )
        # 0 is how an unset env.int arrives; it must not reach the driver as
        # a TTL of zero seconds.
        assert "credential_ttl" not in valkey_iam.configure_options(
            {}, location=TLS_URL, iam_auth=True, credential_ttl=0
        )


class TlsGuardTestCase(SimpleTestCase):
    def test_plaintext_location_is_refused(self):
        # The driver refuses this too, but only when the cache backend is
        # first constructed. Failing at settings load names the bad setting.
        for scheme in ("redis", "valkey"):
            with self.subTest(scheme=scheme):
                with self.assertRaises(ImproperlyConfigured) as ctx:
                    valkey_iam.configure_options(
                        {},
                        location=f"{scheme}://app@cache.example.com:6379/0",
                        iam_auth=True,
                    )
                message = str(ctx.exception)
                assert "VALKEY_URL" in message
                assert "cleartext" in message

    def test_the_error_does_not_offer_the_plaintext_escape(self):
        # django-vcache has credential_provider_allow_plaintext for local
        # development. GlitchTip does not expose it, and the message must not
        # point at it — under deploy pressure that is what gets copied.
        with self.assertRaises(ImproperlyConfigured) as ctx:
            valkey_iam.configure_options(
                {}, location="redis://app@cache:6379/0", iam_auth=True
            )
        assert "allow_plaintext" not in str(ctx.exception)

    def test_tls_schemes_are_accepted(self):
        for scheme in ("valkeys", "rediss", "VALKEYS", "Rediss"):
            with self.subTest(scheme=scheme):
                options = valkey_iam.configure_options(
                    {},
                    location=f"{scheme}://app@cache.example.com:6379/0",
                    iam_auth=True,
                )
                assert (
                    options["credential_provider"]
                    == valkey_iam.ELASTICACHE_IAM_PROVIDER
                )

    def test_sentinel_without_a_ca_bundle_is_refused(self):
        # With sentinel:// the master connection is TLS exactly when
        # ssl_ca_certs is set, so the scheme alone proves nothing.
        with self.assertRaises(ImproperlyConfigured):
            valkey_iam.configure_options(
                {}, location="sentinel://app@sentinel:26379/0", iam_auth=True
            )

    def test_sentinel_with_a_ca_bundle_is_accepted(self):
        options = valkey_iam.configure_options(
            {"ssl_ca_certs": "/certs/ca.pem"},
            location="sentinel://app@sentinel:26379/0",
            iam_auth=True,
        )
        assert options["credential_provider"] == valkey_iam.ELASTICACHE_IAM_PROVIDER
        assert options["ssl_ca_certs"] == "/certs/ca.pem"

    def test_unverified_tls_requires_an_explicit_opt_in(self):
        with self.assertRaises(ImproperlyConfigured) as ctx:
            valkey_iam.configure_options(
                {"ssl_cert_reqs": "none"}, location=TLS_URL, iam_auth=True
            )
        assert "VALKEY_IAM_ALLOW_UNVERIFIED_TLS" in str(ctx.exception)
        options = valkey_iam.configure_options(
            {"ssl_cert_reqs": "none"},
            location=TLS_URL,
            iam_auth=True,
            allow_unverified_tls=True,
        )
        assert options["credential_provider"] == valkey_iam.ELASTICACHE_IAM_PROVIDER
        assert options["ssl_cert_reqs"] == "none"

    def test_verifying_cert_reqs_are_untouched(self):
        for cert_reqs in ("required", "optional"):
            with self.subTest(cert_reqs=cert_reqs):
                options = valkey_iam.configure_options(
                    {"ssl_cert_reqs": cert_reqs}, location=TLS_URL, iam_auth=True
                )
                assert options["ssl_cert_reqs"] == cert_reqs

    def test_unverified_tls_is_allowed_when_nothing_rotates(self):
        options = valkey_iam.configure_options(
            {"ssl_cert_reqs": "none"}, location="redis://cache:6379/0", iam_auth=False
        )
        assert options == {"ssl_cert_reqs": "none"}

    def test_nothing_is_written_when_a_guard_rejects(self):
        # Validated before mutating, so a caller that catches the error is not
        # left with a provider half-wired onto a plaintext LOCATION.
        options = {"ssl_cert_reqs": "none"}
        with self.assertRaises(ImproperlyConfigured):
            valkey_iam.configure_options(
                options, location="redis://app@cache:6379/0", iam_auth=True
            )
        assert options == {"ssl_cert_reqs": "none"}


class IamUserTestCase(SimpleTestCase):
    def test_missing_username_is_refused(self):
        for location in (
            "valkeys://cache.example.com:6379/0",
            "valkeys://@cache.example.com:6379/0",
            "valkeys://:hunter2@cache.example.com:6379/0",
        ):
            with self.subTest(location=location):
                with self.assertRaises(ImproperlyConfigured) as ctx:
                    valkey_iam.configure_options({}, location=location, iam_auth=True)
                assert "valkeys://<iam-user>@host" in str(ctx.exception)

    def test_a_username_is_all_that_is_required(self):
        options = valkey_iam.configure_options(
            {},
            location="valkeys://app-iam-user@cache.example.com:6379/0",
            iam_auth=True,
        )
        assert options["credential_provider"] == valkey_iam.ELASTICACHE_IAM_PROVIDER

    def test_a_generic_provider_does_not_need_a_username(self):
        # Only ElastiCache signs the ACL user into the credential; another
        # issuer may not use one at all.
        options = valkey_iam.configure_options(
            {},
            location="valkeys://cache.example.com:6379/0",
            iam_auth=False,
            credential_provider="myapp.cache.vault_token",
        )
        assert options["credential_provider"] == "myapp.cache.vault_token"


class GenericProviderTestCase(SimpleTestCase):
    def test_generic_provider_is_wired(self):
        options = valkey_iam.configure_options(
            {},
            location=TLS_URL,
            iam_auth=False,
            credential_provider="myapp.cache.vault_token",
            provider_options={"role": "glitchtip"},
            credential_ttl=120,
        )
        assert options["credential_provider"] == "myapp.cache.vault_token"
        assert options["credential_provider_options"] == {"role": "glitchtip"}
        assert options["credential_ttl"] == 120

    def test_generic_provider_gets_the_same_tls_guards(self):
        with self.assertRaises(ImproperlyConfigured):
            valkey_iam.configure_options(
                {},
                location="redis://cache:6379/0",
                iam_auth=False,
                credential_provider="myapp.cache.vault_token",
            )
        with self.assertRaises(ImproperlyConfigured):
            valkey_iam.configure_options(
                {"ssl_cert_reqs": "none"},
                location=TLS_URL,
                iam_auth=False,
                credential_provider="myapp.cache.vault_token",
            )

    def test_iam_auth_and_an_explicit_provider_are_mutually_exclusive(self):
        # One alias has one credential source. Silently preferring one would
        # give an operator who set both an authentication scheme they did not
        # choose.
        with self.assertRaises(ImproperlyConfigured) as ctx:
            valkey_iam.configure_options(
                {},
                location=TLS_URL,
                iam_auth=True,
                credential_provider="myapp.cache.vault_token",
            )
        assert "mutually exclusive" in str(ctx.exception)

    def test_iam_auth_overwrites_an_explicit_options_entry(self):
        # Unlike the TLS options, the credential source is not something an
        # explicit CACHES override may quietly win: IAM auth owns it.
        options = valkey_iam.configure_options(
            {"credential_provider": "myapp.cache.vault_token"},
            location=TLS_URL,
            iam_auth=True,
        )
        assert options["credential_provider"] == valkey_iam.ELASTICACHE_IAM_PROVIDER


def _provider_available():
    """Can the *loaded extension* actually honour credential_provider?

    Checking that ``django_vcache.contrib.aws`` imports is not enough:
    gt_rust re-exports vcache-pyo3's compiled driver as
    ``gt_rust.valkey.RustValkeyDriver``, and that extension is what decides at
    runtime. The Python layer can be new while the extension is old.
    """
    try:
        import inspect

        import_string(valkey_iam.ELASTICACHE_IAM_PROVIDER)
        from gt_rust.valkey import RustValkeyDriver

        return (
            "credential_provider"
            in inspect.signature(RustValkeyDriver.connect).parameters
        )
    except Exception:
        return False


class ProviderWiringTestCase(SimpleTestCase):
    @skipUnless(
        _provider_available(),
        f"{valkey_iam.ELASTICACHE_IAM_PROVIDER} needs a django-vcache with "
        "rotating-credential support; this skip disappears once glitchtip-rust "
        "pins that release. Until then, VALKEY_IAM_AUTH cannot work at runtime.",
    )
    def test_the_configured_provider_is_importable_and_callable(self):
        # The dotted path is resolved by the cache backend at construction, so
        # a typo would otherwise surface only on a deployment with IAM enabled.
        assert callable(import_string(valkey_iam.ELASTICACHE_IAM_PROVIDER))
