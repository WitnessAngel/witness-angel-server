
from django.conf.urls import url

from waserver.apps.wasupport import views

urlpatterns = [
    url(r"^crashdumps/", views.crashdump_report_view),
]
