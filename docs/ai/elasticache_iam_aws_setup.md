# ElastiCache IAM auth — AWS-side setup

The mirror of [RDS IAM auth](rds_iam_aws_setup.md) for the Valkey cache and
task broker. Moved out of django-vcache's `docs/configuration.md`, which
documents only driver-visible behaviour and mentions no cloud vendor beyond
the one provider it ships. This is cloud-account administration and belongs in
GlitchTip's deployment docs — the customer-facing docs site is a separate
repository, so this is not yet placed and still needs a home.

## AWS setup

ElastiCache IAM auth needs all of:

* **Valkey 7.2+ or Redis OSS 7+**. Older engines have no IAM authentication
  mode at all;
* **in-transit encryption enabled** on the cache. AWS requires it for IAM
  auth, because the token is sent as a cleartext `AUTH` argument, and
  `glitchtip/valkey_iam.py` refuses a non-TLS `VALKEY_URL` for the same
  reason;
* an ElastiCache **user with authentication mode `iam`**, whose **user id and
  user name are identical** — AWS does not enforce this, but the token signs
  the user id and the server authenticates the user name, so a mismatch fails
  with an indistinguishable `WRONGPASS`;
* that user in a **user group attached to the cache**. A user that exists but
  is in no attached group authenticates as though the password were wrong;
* an IAM policy granting `elasticache:Connect` on **both** the cache ARN and
  the user ARN (`arn:aws:elasticache:<region>:<account>:user:<user-id>`).
  Granting only one of the two is the common mistake;
* the cache name in **lowercase**. AWS lowercases names at creation, and a
  mixed-case name in the token fails authentication.

The IAM-enabled user goes in the URL userinfo, with no password:

```
VALKEY_URL=valkeys://app-iam-user@my-cache-abc123.serverless.use1.cache.amazonaws.com:6379/0
```

AWS credentials for signing come from the usual chain — task or instance role,
`AWS_PROFILE`, environment.

!!! note "Two ElastiCache limits, both handled by the driver"
    A token is valid for **15 minutes**, and an IAM-authenticated connection
    is **disconnected after 12 hours** unless a fresh `AUTH` is sent on it.
    django-vcache mints a replacement ahead of expiry and re-authenticates
    every live connection with it, which also resets the 12-hour clock. Neither
    limit is anything to configure here.

!!! warning "IAM mode is a one-way door for that user"
    An ElastiCache user's authentication mode is either password or IAM, not
    both. Switching an existing user to IAM stops password authentication for
    it and locks out anything else still connecting as that user. Give IAM
    auth its own ElastiCache user rather than converting one in use.

    It also removes any password fallback, so an IAM or STS outage means no
    new connections. A separate password-mode user in the same user group is
    cheap break-glass insurance.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `VALKEY_IAM_AUTH` | Turn it on. Default off. |
| `VALKEY_IAM_CACHE_NAME` | Lowercase cache name the token signs. Only needed when the endpoint does not reveal it. |
| `VALKEY_IAM_REGION` | e.g. `us-east-1`. Only needed when the endpoint does not reveal it. |
| `VALKEY_IAM_SERVERLESS` | `true`/`false`. Unset lets the provider read it off the endpoint. |
| `VALKEY_IAM_USER_ID` | Defaults to the `VALKEY_URL` username, which is what AWS expects. |
| `VALKEY_IAM_ALLOW_UNVERIFIED_TLS` | Permit `VALKEY_SSL_CERT_REQS=none`. Hands a live token to whatever answers on the hostname. |
| `VALKEY_CREDENTIAL_PROVIDER` | Dotted path to a non-AWS credential issuer. Mutually exclusive with `VALKEY_IAM_AUTH`. |
| `VALKEY_CREDENTIAL_TTL` | Refresh interval for a provider that reports no expiry. Unused with the ElastiCache one. |

The token signs the **cache name** and **user id**, neither of which is the
hostname, so unlike RDS they are not always derivable from the endpoint. The
provider works them out from serverless
(`<name>-<id>.serverless.<region>.cache.amazonaws.com`), cluster-mode
configuration (`clustercfg.<name>…`) and primary/reader (`master.<name>…`,
`replica.<name>…`) endpoints, and reads the region abbreviation (`use1` →
`us-east-1`) from a built-in table. A **node endpoint**, a **CNAME**, or a
region not in that table needs `VALKEY_IAM_CACHE_NAME` and
`VALKEY_IAM_REGION` set explicitly.

## The task broker needs nothing extra

django-vtasks reaches Valkey through the `default` cache alias's
`cache.get_raw_client()`, so the broker uses the same driver and the same
rotating credential as the cache. There is no separate broker URL to
authenticate.

## What is not verified here

The AWS-side details above are reasoned from how ElastiCache IAM auth is
documented to work and from what the provider signs; the settings-level policy
(`glitchtip/test_valkey_iam.py`) is tested, an end-to-end run against a real
IAM-enabled cache is not. django-vcache's `scripts/elasticache_e2e.py`
exercises the driver half against a real cache and can soak past both the
15-minute and 12-hour limits.
