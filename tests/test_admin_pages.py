
import pytest
from waserver.apps.wagateway.models import PublicAuthenticator, RevelationRequest
from model_bakery import baker


@pytest.mark.django_db
def test_admin_listing_pages(client):

    superuser = baker.make("auth.User", is_superuser=True, is_staff=True, is_active=True)
    client.force_login(superuser)

    public_authenticator = baker.make("wagateway.PublicAuthenticator")
    public_authenticator_key = baker.make("wagateway.PublicAuthenticatorKey",
                                          public_authenticator=public_authenticator,
                                          key_value=b"sjdshd")
    revelation_request = baker.make("wagateway.RevelationRequest",
                                    target_public_authenticator=public_authenticator,
                                    revelation_response_public_key=b"dgzer")
    symkey_decryption_request = baker.make("wagateway.SymkeyDecryptionRequest",
                                           target_public_authenticator_key=public_authenticator_key,
                                           revelation_request=revelation_request,
                                           symkey_decryption_request_data=b"xwsd",
                                           symkey_decryption_response_data=b"xwsd")

    admin_endpoint_confs = [
        ("/admin/wagateway/publicauthenticator/", PublicAuthenticator),
        ("/admin/wagateway/revelationrequest/", RevelationRequest),
    ]

    for admin_listing_url, model_class in admin_endpoint_confs:
        response = client.get(admin_listing_url)  # Simple listing
        assert response.status_code == 200
        response = client.get(admin_listing_url + "add/")  # ADD page
        assert response.status_code == 200
        instance_pk = model_class.objects.first().pk
        response = client.get(admin_listing_url + "%d/change/" % instance_pk)  # EDIT page
        assert response.status_code == 200
