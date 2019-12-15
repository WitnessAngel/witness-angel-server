from django.core.management.base import BaseCommand

from django.core.management.base import BaseCommand

from wacryptolib.escrow import generate_free_keypair_for_least_provisioned_key_type
from waescrow.escrow import SqlKeyStorage


class Command(BaseCommand):
    help = "Pregenerate free keys for escrow webservices."

    def add_arguments(self, parser):
        parser.add_argument("max_free_keys_per_type", nargs="?", type=int, default=10)

    def handle(self, *args, **options):

        max_free_keys_per_type = options["max_free_keys_per_type"]

        sql_key_storage = SqlKeyStorage()

        self.stdout.write(
            "Launching generate_free_keys.py script with max_free_keys_per_type=%s"
            % max_free_keys_per_type
        )

        while True:
            self.stdout.write(
                "New iteration of generate_free_keypair_for_least_provisioned_key_type()"
            )
            has_generated = generate_free_keypair_for_least_provisioned_key_type(
                key_storage=sql_key_storage,
                max_free_keys_per_type=max_free_keys_per_type,
            )
            if not has_generated:
                self.stdout.write(
                    "No more need for additional free keys, stopping generate_free_keys.py script"
                )
                break
