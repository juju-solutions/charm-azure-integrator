import json
from base64 import b64encode
from unittest.mock import Mock, patch

from charmhelpers.core import hookenv
from charms.reactive import set_flag

from charms import layer
from reactive import azure as reactive_azure


def test_series_upgrade():
    layer.status.blocked.reset_mock()
    assert layer.status.blocked.call_count == 0
    reactive_azure.pre_series_upgrade()
    assert layer.status.blocked.call_count == 1


@patch.object(reactive_azure, "get_credentials")
@patch.object(layer, "azure")
def test_update_roles_on_install(lib_azure, get_credentials):
    get_credentials.return_value = {"managed-identity": False}
    reactive_azure.update_roles_on_install()
    assert not lib_azure.update_roles.called

    get_credentials.return_value = {"managed-identity": True}
    reactive_azure.update_roles_on_install()
    assert lib_azure.update_roles.called


@patch.object(reactive_azure, "get_credentials")
@patch.object(layer, "azure")
def test_update_roles_on_upgrade(lib_azure, get_credentials):
    reactive_azure.update_roles()
    assert not get_credentials.called
    assert not lib_azure.update_roles.called

    set_flag("charm.azure.creds.set")
    get_credentials.return_value = {"managed-identity": False}
    reactive_azure.update_roles()
    assert get_credentials.called
    assert not lib_azure.update_roles.called

    get_credentials.return_value = {"managed-identity": True}
    reactive_azure.update_roles()
    assert lib_azure.update_roles.called


@patch.object(reactive_azure, "get_credentials")
@patch.object(layer, "azure")
def test_handle_requests(lib_azure, get_credentials):
    get_credentials.return_value = {"managed-identity": False}
    ep = reactive_azure.endpoint_from_name.return_value
    ep.requests = [Mock()]
    reactive_azure.handle_requests()
    assert lib_azure.send_additional_metadata.called
    assert not lib_azure.ensure_msi.called
    assert ep.mark_completed.call_count == 1

    ep.mark_completed.reset_mock()
    get_credentials.return_value = {"managed-identity": True}
    reactive_azure.handle_requests()
    assert lib_azure.ensure_msi.called
    assert ep.mark_completed.call_count == 1


@patch.object(layer.azure, "get_credentials")
@patch.object(layer.azure, "_azure")
def test_send_additional_metadata(_azure, get_credentials):
    hookenv.config.return_value = {
        "vnetSecurityGroupResourceGroup": "vnet-sg",
    }
    get_credentials.return_value = {
        "managed-identity": "mi",
        "application-id": "aid",
        "application-password": "apwd",
        "tenant-id": "tid",
    }
    _azure.return_value = {"location": "loc"}
    request = Mock(resource_group="rg")
    layer.azure.send_additional_metadata(request)
    request.send_additional_metadata.assert_called_with(
        resource_group_location="loc",
        vnet_name="juju-internal-network",
        vnet_resource_group="rg",
        subnet_name="juju-internal-subnet",
        security_group_name="juju-internal-nsg",
        security_group_resource_group="vnet-sg",
        use_managed_identity="mi",
        aad_client="aid",
        aad_secret="apwd",
        tenant_id="tid",
    )


@patch.object(layer.azure, "login_cli")
@patch("subprocess.run")
def test_get_credentials(run, login_cli):
    layer.status.blocked.reset_mock()
    run.side_effect = FileNotFoundError
    hookenv.config.return_value = {"credentials": ""}
    assert layer.azure.get_credentials() == {}
    assert layer.status.blocked.called

    layer.status.blocked.reset_mock()
    run.side_effect = None
    run().stdout = "{'credential': {'attributes': {'foo': 'bar'}}}".encode("utf8")
    assert layer.azure.get_credentials() == {
        "foo": "bar",
        "managed-identity": True,
    }
    assert not layer.status.blocked.called

    layer.status.blocked.reset_mock()
    hookenv.config.return_value = {"credentials": "foo"}
    assert layer.azure.get_credentials() == {}
    assert layer.status.blocked.called
    assert layer.status.blocked.call_args[0] == (
        "invalid value for credentials config",
    )

    layer.status.blocked.reset_mock()
    hookenv.config.return_value = {
        "credentials": b64encode(
            json.dumps(
                {
                    "foo": "qux",
                    "managed-identity": False,
                }
            ).encode("utf8")
        )
    }
    assert layer.azure.get_credentials() == {
        "foo": "qux",
        "managed-identity": False,
    }
    assert not layer.status.blocked.called
