import secrets

from django.db import migrations


def create_key(apps, schema_editor):
    """Create the public id key, once.

    Must survive squashes: a fresh database gets its key from here, and
    nothing else creates one.
    """
    PublicIdKey = apps.get_model("organizations_ext", "PublicIdKey")
    if not PublicIdKey.objects.exists():
        PublicIdKey.objects.create(id=1, key=secrets.token_hex(32))


class Migration(migrations.Migration):
    dependencies = [
        ("organizations_ext", "0018_publicidkey"),
    ]

    operations = [
        # Reverse is a no-op so that unapplying and reapplying this migration
        # keeps the key, and with it every public org id.
        migrations.RunPython(create_key, migrations.RunPython.noop),
    ]
