

from django.conf.urls import url
from django.urls import path, include
from rest_framework import routers

from waserver.apps.wagateway import views
from waserver.apps.wagateway.views import wagateway_extended_jsonrpc_site

router = routers.DefaultRouter()
router.register(r'rest/public-authenticators', views.PublicAuthenticatorViewSet)
# router.register(r'publicauthenticator', views.PublicAuthenticatorViewSet)

urlpatterns = [
    path('', include(router.urls)),
    # USELESS login/logout - path('rest-auth/', include('rest_framework.urls', namespace='wagateway_rest')),
    url(r"^jsonrpc/", wagateway_extended_jsonrpc_site.dispatch, name="wagateway_jsonrpc"),
]
