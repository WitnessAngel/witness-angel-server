# This file is part of Witness Angel Server
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from django.conf.urls import url

from .views import watrustee_extended_jsonrpc_site

urlpatterns = [
    # url(r"^jsonrpc/browse/", jsonrpc.views.browse, name="jsonrpc_browser"),
    url(r"^jsonrpc/", watrustee_extended_jsonrpc_site.dispatch, name="watrustee_jsonrpc")
]
