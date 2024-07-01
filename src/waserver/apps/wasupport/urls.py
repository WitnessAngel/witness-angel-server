# This file is part of Witness Angel Server
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from django.conf.urls import url

from waserver.apps.wasupport import views

urlpatterns = [url(r"^crashdumps/", views.crashdump_report_view)]
