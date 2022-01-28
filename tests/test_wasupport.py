
import random
from django.conf import settings
from django.test import Client


def test_crashdump_reports(db):

    crashdump_url = "/support/crashdumps/"

    client = Client(enforce_csrf_checks=True)

    crashdump = "sòme dâta %s" % random.randint(1, 10000)

    res = client.get(crashdump_url)
    assert res.status_code == 200
    assert res.content == b"CRASHDUMP ENDPOINT OF WASERVER"

    res = client.post(crashdump_url)
    assert res.status_code == 400
    assert res.content == b"Missing crashdump field"

    res = client.post(crashdump_url, data=dict(crashdump=crashdump))
    assert res.status_code == 200
    assert res.content == b"OK"

    dump_files = sorted(settings.CRASHDUMPS_DIR.iterdir())
    assert dump_files
    dump_file_content = dump_files[-1].read_text(encoding="utf8")
    assert dump_file_content == crashdump
