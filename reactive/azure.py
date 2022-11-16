from traceback import format_exc

from charmhelpers.core import unitdata
from charms.reactive import (
    when_all,
    when_any,
    when_not,
    set_flag,
    toggle_flag,
    clear_flag,
    hook,
    is_flag_set
)
from charms.reactive.relations import endpoint_from_name
from charms import layer
from charms.layer.azure import get_credentials


@hook('update-status')
def update_status():
    # need to recheck creds in case the credentials from Juju have changed
    clear_flag('charm.azure.creds.set')


@when_any("config.changed.credentials")
def update_creds():
    clear_flag("charm.azure.creds.set")


@when_all("apt.installed.azure-cli")
@when_not("charm.azure.creds.set")
def get_creds():
    db = unitdata.kv()

    prev_creds = db.get("charm.azure.creds")
    creds = get_credentials()
    db.set("charm.azure.creds", creds)

    toggle_flag("charm.azure.creds.set", creds)
    if creds != prev_creds:
        set_flag("charm.azure.creds.changed")


@when_all("apt.installed.azure-cli", "charm.azure.creds.set")
@when_not("charm.azure.initial-role-update")
def update_roles_on_install():
    layer.status.maintenance("loading roles")
    if get_credentials()["managed-identity"]:
        layer.azure.update_roles()
    set_flag("charm.azure.initial-role-update")
    layer.status.active("Ready")


@when_all(
    "apt.installed.azure-cli",
    "charm.azure.creds.set",
    "charm.azure.initial-role-update",
)
@when_not("endpoint.clients.requests-pending")
def no_requests():
    layer.azure.cleanup()
    layer.status.active("Ready")


@when_all(
    "apt.installed.azure-cli",
    "charm.azure.creds.set",
    "charm.azure.initial-role-update",
)
@when_any(
    "charm.azure.creds.changed",
    "config.changed",
    "endpoint.clients.requests-pending"
)
def handle_requests():
    azure = endpoint_from_name("clients")
    creds_data = get_credentials()
    config_changed = is_flag_set("config.changed")
    creds_changed = is_flag_set("charm.azure.creds.changed")
    refresh_requests = config_changed or creds_changed
    requests = azure.all_requests if refresh_requests else azure.requests
    try:
        for request in requests:
            layer.status.maintenance(
                "Granting request for {} ({})".format(
                    request.vm_name, request.unit_name
                )
            )
            layer.azure.send_additional_metadata(request)
            if not creds_data["managed-identity"]:
                # We don't need to perform operations on the VMs.
                # The Service Principal is taking care of ops.
                continue
            layer.azure.ensure_msi(request)
            if request.instance_tags:
                layer.azure.tag_instance(request)
            if request.requested_loadbalancer_management:
                layer.azure.enable_loadbalancer_management(request)
            if request.requested_instance_inspection:
                layer.azure.enable_instance_inspection(request)
            if request.requested_network_management:
                layer.azure.enable_network_management(request)
            if request.requested_security_management:
                layer.azure.enable_security_management(request)
            if request.requested_block_storage_management:
                layer.azure.enable_block_storage_management(request)
            if request.requested_dns_management:
                layer.azure.enable_dns_management(request)
            if request.requested_object_storage_access:
                layer.azure.enable_object_storage_access(request)
            if request.requested_object_storage_management:
                layer.azure.enable_object_storage_management(request)
            layer.azure.log(
                "Finished request for {} ({})".format(
                    request.vm_name, request.unit_name
                )
            )
        azure.mark_completed()
    except layer.azure.AzureError:
        layer.azure.log_err(format_exc())
        layer.status.blocked(
            "error while granting requests; " "check credentials and debug-log"
        )
    clear_flag("charm.azure.creds.changed")


@when_any("endpoint.lb-consumers.requests_changed")
def manage_lbs():
    lb_consumers = endpoint_from_name("lb-consumers")
    for request in lb_consumers.new_requests:
        _create_lb(request)
        lb_consumers.send_response(request)

    for request in lb_consumers.removed_requests:
        layer.azure.remove_loadbalancer(request)


def _create_lb(request):
    request.response.error = None
    request.response.error_message = None
    request.response.error_fields = {}
    try:
        request.response.address = layer.azure.create_loadbalancer(request)
        if not request.response.address:
            request.response.error = request.response.error_types.provider_error
            request.response.error_message = "no address returned by provider"
    except layer.azure.LoadBalancerException as e:
        request.response.error = request.response.error_types.provider_error
        request.response.error_message = e.message
    except layer.azure.LoadBalancerUnsupportedFeatureException as e:
        request.response.error = request.response.error_types.unsupported
        request.response.error_fields = e.error_fields


@hook("stop")
def cleanup():
    lb_consumers = endpoint_from_name("lb-consumers")
    # These are expected to both always be empty lists (since the relations should have
    # already been removed by this point), but we do this anyway JIC.
    for request in lb_consumers.all_requests + lb_consumers.removed_requests:
        layer.azure.remove_loadbalancer(request)


@hook("upgrade-charm")
def update_roles():
    if not is_flag_set("charm.azure.creds.set"):
        return
    if not get_credentials()["managed-identity"]:
        return
    layer.azure.update_roles()

    lb_consumers = endpoint_from_name("lb-consumers")
    for request in lb_consumers.all_requests:
        _create_lb(request)
        lb_consumers.send_response(request)


@hook("pre-series-upgrade")
def pre_series_upgrade():
    layer.status.blocked("Series upgrade in progress")
