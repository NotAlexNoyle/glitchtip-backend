import secrets

from django.db import migrations


def create_key(apps, schema_editor):
    """Create the public org id key, once.

    Must survive squashes: a fresh database gets its key from here, and
    nothing else creates one.
    """
    OrgIdKey = apps.get_model("organizations_ext", "OrgIdKey")
    if not OrgIdKey.objects.exists():
        OrgIdKey.objects.create(id=1, key=secrets.token_hex(32))


class Migration(migrations.Migration):
    dependencies = [
        ("organizations_ext", "0018_orgidkey"),
    ]

    operations = [
        # Reverse is a no-op so that unapplying and reapplying this migration
        # keeps the key, and with it every public org id.
        migrations.RunPython(create_key, migrations.RunPython.noop),
    ]
