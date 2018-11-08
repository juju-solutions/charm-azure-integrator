from traceback import format_exc

from charms.reactive import (
    when_all,
    when_any,
    when_not,
    toggle_flag,
    clear_flag,
    hook,
)
from charms.reactive.relations import endpoint_from_name

from charms import layer


@when_any('config.changed.credentials')
def update_creds():
    clear_flag('charm.azure.creds.set')


@when_all('apt.installed.azure-cli')
@when_not('charm.azure.creds.set')
def get_creds():
    toggle_flag('charm.azure.creds.set', layer.azure.get_credentials())


@when_all('apt.installed.azure-cli',
          'charm.azure.creds.set')
@when_not('endpoint.clients.requests-pending')
def no_requests():
    layer.azure.cleanup()
    layer.status.active('ready')


@when_all('apt.installed.azure-cli',
          'charm.azure.creds.set',
          'endpoint.clients.requests-pending')
def handle_requests():
    azure = endpoint_from_name('clients')
    try:
        for request in azure.requests:
            layer.status.maintenance('Granting request for {} ({})'.format(
                request.vm_name,
                request.unit_name))
            layer.azure.ensure_msi(request)
            layer.azure.send_additional_metadata(request)
            if request.instance_tags:
                layer.azure.tag_instance(request)
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
            layer.azure.log('Finished request for {} ({})'.format(
                request.vm_name,
                request.unit_name))
        azure.mark_completed()
    except layer.azure.AzureError:
        layer.azure.log_err(format_exc())
        layer.status.blocked('error while granting requests; '
                             'check credentials and debug-log')


@hook('upgrade-charm')
def update_roles():
    layer.azure.update_roles()
