from importlib import import_module
from unittest.mock import patch

from django.apps import apps as django_apps
from django.test import TestCase
from django.urls import reverse
from model_bakery import baker

from apps.api_tokens.models import APIToken
from apps.organizations_ext.constants import OrganizationUserRole

migration = import_module("apps.users.migrations.0013_populate_user_and_token")
TOKEN = "a" * 64


class ProvisionUserAndTokenTestCase(TestCase):
    @patch.dict(
        "os.environ",
        {
            "INITIAL_USER_EMAIL": "admin@example.com",
            "INITIAL_USER_PASSWORD": "provisioned-password",
            "INITIAL_USER_AUTH_TOKEN": TOKEN,
        },
    )
    def test_provisioned_token_can_read_what_it_creates(self):
        """Bootstrap scripts create a project, then read its keys for the DSN."""
        migration.provision_user_and_token(django_apps, None)

        token = APIToken.objects.select_related("user").get(token=TOKEN)
        self.assertTrue(token.user.is_superuser)
        self.assertEqual(
            set(token.get_scopes()),
            {
                f"{family}:{level}"
                for family in ("project", "team", "event", "org", "member")
                for level in ("read", "write", "admin")
            },
        )

        organization = baker.make("organizations_ext.Organization")
        organization.add_user(token.user, OrganizationUserRole.OWNER)
        project = baker.make("projects.Project", organization=organization)
        res = self.client.get(
            reverse("api:list_project_keys", args=[organization.slug, project.slug]),
            headers={"authorization": f"Bearer {TOKEN}"},
        )
        self.assertEqual(res.status_code, 200)
