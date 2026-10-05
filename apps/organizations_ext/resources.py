from import_export import fields, resources

from .models import Organization, OrganizationUser
from .public_id import encode


class OrganizationResource(resources.ModelResource):
    # Export only: rows are still matched on import by the internal id.
    public_id = fields.Field(column_name="public_id", readonly=True)

    class Meta:
        model = Organization
        skip_unchanged = True
        fields = ("id", "public_id", "slug", "name", "created", "organization")

    def dehydrate_public_id(self, organization):
        return str(encode(organization.id))


class OrganizationUserResource(resources.ModelResource):
    class Meta:
        model = OrganizationUser
        skip_unchanged = True
        fields = (
            "id",
            "user",
            "organization",
            "role",
            "email",
        )
        import_id_fields = ("user", "email", "organization")
