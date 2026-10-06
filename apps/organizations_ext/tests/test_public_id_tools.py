from django.test import TestCase
from django.urls import reverse
from model_bakery import baker

from apps.organizations_ext.public_id import encode
from apps.organizations_ext.resources import OrganizationResource


class PublicIdSupportToolsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization", name="Acme Corp")
        cls.other = baker.make("organizations_ext.Organization", name="Other")
        cls.public = str(encode(cls.org.id))

    def setUp(self):
        admin = baker.make("users.User", is_staff=True, is_superuser=True)
        self.client.force_login(admin)

    def test_admin_shows_both_ids(self):
        changelist = self.client.get(
            reverse("admin:organizations_ext_organization_changelist")
        )
        self.assertContains(changelist, self.public)
        change = self.client.get(
            reverse("admin:organizations_ext_organization_change", args=[self.org.id])
        )
        self.assertContains(change, self.public)

    def test_admin_search_finds_an_org_by_either_id_or_slug(self):
        url = reverse("admin:organizations_ext_organization_changelist")
        for term in (self.public, str(self.org.id), "acme-corp"):
            with self.subTest(term=term):
                res = self.client.get(url, {"q": term})
                self.assertEqual(list(res.context["cl"].result_list), [self.org])

    def test_export_has_the_public_id(self):
        dataset = OrganizationResource().export()
        rows = {str(row["id"]): row["public_id"] for row in dataset.dict}
        self.assertEqual(rows[str(self.org.id)], self.public)
