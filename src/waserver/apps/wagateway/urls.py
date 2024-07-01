# This file is part of Witness Angel Server
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from django.conf.urls import url

from waserver.apps.wagateway.views import wagateway_extended_jsonrpc_site

urlpatterns = [
    # USELESS FOR NOW - login/logout - path('rest-auth/', include('rest_framework.urls', namespace='wagateway_rest')),
    url(r"^jsonrpc/", wagateway_extended_jsonrpc_site.dispatch, name="wagateway_jsonrpc")
]
