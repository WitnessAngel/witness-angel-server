# This file is part of Witness Angel Server
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)


@csrf_exempt
def crashdump_report_view(request):
    if request.method == "GET":
        return HttpResponse(b"CRASHDUMP ENDPOINT OF WASERVER")

    crashdump = request.POST.get("crashdump")
    if not crashdump:
        logger.warning("Empty crashdump report received")
        return HttpResponseBadRequest(b"Missing crashdump field")

    filename = timezone.now().strftime("%Y%m%d-%H%M%S-%f.dump")
    logger.info("Got http request on crashdump report view (%s chars), stored in %s", len(crashdump), filename)

    crashdump_path = settings.CRASHDUMPS_DIR.joinpath(filename)
    crashdump_path.write_text(crashdump, encoding="utf8")
    return HttpResponse(b"OK")
