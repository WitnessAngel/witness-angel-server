from io import StringIO

from django.core.management import call_command

from waescrow.escrow import SqlKeyStorage


def test_generate_free_keys(db):

    sql_key_storage = SqlKeyStorage()

    assert sql_key_storage.get_free_keypairs_count("RSA_OAEP") == 0

    out_stream = StringIO()
    call_command("generate_free_keys", "1", stdout=out_stream)
    output = out_stream.getvalue()
    print(output)

    assert "Launching generate_free_keys.py script with max_free_keys_per_type=1" in output
    assert "No more need for additional free keys" in output

    assert output.count("New iteration") == 5  # 1 key x 4 key types, and final iteration for nothing
    assert sql_key_storage.get_free_keypairs_count("RSA_OAEP") == 1
