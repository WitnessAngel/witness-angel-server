
from django.conf.urls import url


from .views import watrustee_extended_jsonrpc_site


urlpatterns = [
    # url(r"^jsonrpc/browse/", jsonrpc.views.browse, name="jsonrpc_browser"),
    url(r"^jsonrpc/", watrustee_extended_jsonrpc_site.dispatch, name="watrustee_jsonrpc"),
]
