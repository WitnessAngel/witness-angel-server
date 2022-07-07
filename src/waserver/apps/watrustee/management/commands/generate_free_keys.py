from django.core.management.base import BaseCommand

from wacryptolib.keystore import generate_free_keypair_for_least_provisioned_key_algo
from waserver.apps.watrustee.core import SqlKeystore


class Command(BaseCommand):
    help = "Pregenerate free keys for trustee webservices."

    def add_arguments(self, parser):
        parser.add_argument("max_free_keys_per_algo", nargs="?", type=int, default=10)

    def handle(self, *args, **options):

        max_free_keys_per_algo = options["max_free_keys_per_algo"]

        sql_keystore = SqlKeystore()

        self.stdout.write(
            "Launching generate_free_keys.py script with max_free_keys_per_algo=%s" % max_free_keys_per_algo
        )

        while True:
            self.stdout.write("New iteration of generate_free_keypair_for_least_provisioned_key_algo()")
            has_generated = generate_free_keypair_for_least_provisioned_key_algo(
                keystore=sql_keystore, max_free_keys_per_algo=max_free_keys_per_algo
            )
            if not has_generated:
                self.stdout.write("No more need for additional free keys, stopping generate_free_keys.py script")
                break
