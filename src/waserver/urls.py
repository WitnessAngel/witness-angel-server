
from django.urls import include, path
from django.contrib import admin
from django.contrib.admindocs import urls as admindocs_urls
from django.views.generic import TemplateView


admin.autodiscover()


urlpatterns = [
    # django-admin:
    #path("admin/doc/", include(admindocs_urls)),
    path("admin/", admin.site.urls),
    # Text and xml static files:
    path(
        "robots.txt",
        TemplateView.as_view(template_name="txt/robots.txt", content_type="text/plain"),
        name="robots_txt",
    ),
    # Webservices:
    path("gateway/", include(("waserver.apps.wagateway.urls", "wagateway"), namespace="wagateway_api")),
    path("trustee/", include(("waserver.apps.watrustee.urls", "watrustee"), namespace="watrustee_api")),
    path("support/", include(("waserver.apps.wasupport.urls", "wasupport"), namespace="wasupport_api")),
]


#if settings.DEBUG:  # pragma: no cover
    #import debug_toolbar  # noqa: Z435
    #urlpatterns = [
    #    # URLs specific only to django-debug-toolbar:
    #    path(r"__debug__", include(debug_toolbar.urls)),  # noqa: DJ05
    #] + urlpatterns

