import json
import os
import re
import subprocess
from base64 import b64decode
from enum import Enum
from math import ceil, floor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import yaml

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


ENTITY_PREFIX = 'charm.azure'
MODEL_UUID = os.environ['JUJU_MODEL_UUID']
MAX_ROLE_NAME_LEN = 64
MAX_POLICY_NAME_LEN = 128


class StandardRole(Enum):
    NETWORK_MANAGER = '4d97b98b-1d4f-4787-a291-c67834d212e7'
    SECURITY_MANAGER = 'e3d13bf0-dd5a-482e-ba6b-9b8433878d10'
    DNS_MANAGER = 'befefa01-2a29-4197-83a8-272ff33ce314'
    OBJECT_STORE_READER = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
    OBJECT_STORE_MANAGER = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'


# When debugging hooks, for some reason HOME is set to /home/ubuntu, whereas
# during normal hook execution, it's /root. Set it here to be consistent.
os.environ['HOME'] = '/root'


def log(msg, *args):
    hookenv.log(msg.format(*args), hookenv.INFO)


def log_debug(msg, *args):
    hookenv.log(msg.format(*args), hookenv.DEBUG)


def log_err(msg, *args):
    hookenv.log(msg.format(*args), hookenv.ERROR)


def get_credentials():
    """
    Get the credentials from either the config or the hook tool.

    Prefers the config so that it can be overridden.
    """
    no_creds_msg = 'missing credentials; set credentials config'
    config = hookenv.config()
    # try to use Juju's trust feature
    try:
        result = subprocess.run(['credential-get'],
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        creds = yaml.load(result.stdout.decode('utf8'))
        creds_data = creds['credential']['attributes']
        login_cli(creds_data)
        return True
    except FileNotFoundError:
        pass  # juju trust not available
    except subprocess.CalledProcessError as e:
        if 'permission denied' not in e.stderr.decode('utf8'):
            raise
        no_creds_msg = 'missing credentials access; grant with: juju trust'

    # try credentials config
    if config['credentials']:
        try:
            creds_data = b64decode(config['credentials']).decode('utf8')
            login_cli(json.loads(creds_data))
            return True
        except Exception as ex:
            msg = 'invalid value for credentials config'
            log_debug('{}: {}', msg, ex)
            status.blocked(msg)
            return False

    # no creds provided
    status.blocked(no_creds_msg)
    return False


def login_cli(creds_data):
    """
    Use the credentials to authenticate the Azure CLI.
    """
    app_id = creds_data['application-id']
    app_pass = creds_data['application-password']
    sub_id = creds_data['subscription-id']
    tenant_id = _get_tenant_id(sub_id)
    try:
        log('Forcing logout of Azure CLI')
        _azure('logout')
    except AzureError:
        pass
    try:
        log('Logging in to Azure CLI')
        _azure('login',
               '--service-principal',
               '-u', app_id,
               '-p', app_pass,
               '-t', tenant_id)
        # cache the subscription ID for use in roles
        kv().set('charm.azure.sub-id', sub_id)
    except AzureError as e:
        # redact the credential info from the exception message
        stderr = re.sub(app_id, '<app-id>', e.args[0])
        stderr = re.sub(app_pass, '<app-pass>', stderr)
        stderr = re.sub(tenant_id, '<tenant-id>', stderr)
        # from None suppresses the previous exception from the stack trace
        raise AzureError(stderr) from None


def ensure_msi(request):
    msi = _get_msi(request.vm_id)
    if not msi:
        log('Enabling Managed Service Identity')
        result = _azure('vm', 'identity', 'assign',
                        '--name', request.vm_name,
                        '--resource-group', request.resource_group)
        vm_identities = kv().get('charm.azure.vm-identities', {})
        msi = vm_identities[request.vm_id] = result['systemAssignedIdentity']
        kv().set('charm.azure.vm-identities', vm_identities)
    log('Instance MSI is: {}', msi)


def send_additional_metadata(request):
    """
    Get additional info about the requesting instance via the API that isn't
    available from the metadata server.
    """
    run_config = hookenv.config() or {}
    res_grp = _azure('group', 'show', '--name', request.resource_group)
    # hard-code most of these because with Juju, they're always the same
    # and the queries required to look them up are a PITA
    request.send_additional_metadata(
        resource_group_location=res_grp['location'],
        vnet_name=run_config.get('vnetName') if run_config.get('vnetName') else 'juju-internal-network',
        vnet_resource_group=run_config.get('vnetResourceGroup') if run_config.get('vnetResourceGroup') else request.resource_group,
        subnet_name=run_config.get('subnetName') if run_config.get('subnetName') else 'juju-internal-subnet',
        security_group_name=run_config.get('vnetSecurityGroup') if run_config.get('vnetSecurityGroup') else 'juju-internal-nsg',
    )


def tag_instance(request):
    """
    Tag the given instance with the given tags.
    """
    log('Tagging instance with: {}', request.instance_tags)
    _azure('vm', 'update',
           '--name', request.vm_name,
           '--resource-group', request.resource_group,
           '--set', *['tags.{}={}'.format(tag, value)
                      for tag, value in request.instance_tags.items()])


def enable_instance_inspection(request):
    """
    Enable instance inspection access for the given application.
    """
    log('Enabling instance inspection')
    _assign_role(request, _get_role('vm-reader'))


def enable_network_management(request):
    """
    Enable network management for the given application.
    """
    log('Enabling network management')
    _assign_role(request, StandardRole.NETWORK_MANAGER)


def enable_loadbalancer_management(request):
    """
    Enable network management for the given application.
    """
    log('Enabling load balancer management')
    _assign_role(request, _get_role('lb-manager'))


def enable_security_management(request):
    """
    Enable security management for the given application.
    """
    log('Enabling security management')
    _assign_role(request, StandardRole.SECURITY_MANAGER)


def enable_block_storage_management(request):
    """
    Enable block storage (disk) management for the given application.
    """
    log('Enabling block storage management')
    _assign_role(request, _get_role('disk-manager'))


def enable_dns_management(request):
    """
    Enable DNS management for the given application.
    """
    log('Enabling DNS management')
    _assign_role(request, StandardRole.DNS_MANAGER)


def enable_object_storage_access(request):
    """
    Enable object storage read-only access for the given application.
    """
    log('Enabling object storage read')
    _assign_role(request, StandardRole.OBJECT_STORE_READER)


def enable_object_storage_management(request):
    """
    Enable object storage management for the given application.
    """
    log('Enabling object store management')
    _assign_role(request, StandardRole.OBJECT_STORE_MANAGER)


def cleanup():
    """
    Perform cleanup.
    """
    pass


def update_roles():
    """
    Update all custom roles based on current definition file.
    """
    sub_id = kv().get('charm.azure.sub-id')
    known_roles = {}
    for role_file in Path('files/roles/').glob('*.json'):
        role_name = role_file.stem
        role_data = json.loads(role_file.read_text())
        role_fullname = role_data['Name'].format(sub_id)
        scope = role_data['AssignableScopes'][0].format(sub_id)
        role_data['Name'] = role_fullname
        role_data['AssignableScopes'][0] = scope
        try:
            # assume already exists, so try updating first
            _azure('role', 'definition', 'update',
                   '--role-definition', json.dumps(role_data))
            log('Updated existing role {}', role_fullname)
        except DoesNotExistAzureError:
            # doesn't exist, so create
            _azure('role', 'definition', 'create',
                   '--role-definition', json.dumps(role_data))
            log('Created new role {}', role_fullname)
        known_roles[role_name] = role_fullname
    kv().set('charm.azure.roles', known_roles)


# Internal helpers


class AzureError(Exception):
    """
    Exception class representing an error returned from the azure-cli tool.
    """
    @classmethod
    def get(cls, message):
        """
        Factory method to create either an instance of this class or a
        meta-subclass for certain `message`s.
        """
        if 'already exists' in message:
            return AlreadyExistsAzureError(message)
        if 'Please provide' in message and 'an existing' in message:
            return DoesNotExistAzureError(message)
        if 'No definition was found' in message:
            return DoesNotExistAzureError(message)
        return AzureError(message)


class AlreadyExistsAzureError(AzureError):
    """
    Meta-error subclass of AzureError representing something already existing.
    """
    pass


class DoesNotExistAzureError(AzureError):
    """
    Meta-error subclass of AzureError representing something not existing.
    """
    pass


def _elide(s, max_len, ellipsis='...'):
    """
    Elide s in the middle to ensure it is under max_len.

    That is, shorten the string, inserting an ellipsis where the removed
    characters were to show that they've been removed.
    """
    if len(s) > max_len:
        hl = (max_len - len(ellipsis)) / 2
        headl, taill = floor(hl), ceil(hl)
        s = s[:headl] + ellipsis + s[-taill:]
    return s


def _get_tenant_id(subscription_id):
    """
    Translate the subscription ID into a tenant ID by making an unauthorized
    request to the API and extracting the tenant ID from the WWW-Authenticate
    header in the error response.
    """
    url = ('https://management.azure.com/subscriptions/'
           '{}?api-version=2018-03-01-01.6.1'.format(subscription_id))
    try:
        urlopen(url)
        log_err('Error getting tenant ID: did not get "unauthorized" response')
        return None
    except HTTPError as e:
        if 'WWW-Authenticate' not in e.headers:
            log_err('Error getting tenant ID: missing WWW-Authenticate header')
            return None
        www_auth = e.headers['WWW-Authenticate']
        match = re.search(r'authorization_uri="[^"]*/([^/"]*)"', www_auth)
        if not match:
            log_err('Error getting tenant ID: unable to find in {}', www_auth)
            return None
        return match.group(1)


def _azure(cmd, *args, return_stderr=False):
    """
    Call the azure-cli tool.
    """
    cmd = ['az', cmd]
    cmd.extend(args)
    result = subprocess.run(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout = result.stdout.decode('utf8').strip()
    stderr = result.stderr.decode('utf8').strip()
    if result.returncode != 0:
        raise AzureError.get(stderr)
    if return_stderr:
        return stderr
    if stdout:
        stdout = json.loads(stdout)
    return stdout


def _get_msi(vm_id):
    """
    Get the Managed System Identity for the VM.
    """
    vm_identities = kv().get('charm.azure.vm-identities', {})
    return vm_identities.get(vm_id)


def _get_role(role_name):
    """
    Translate short role name into a full role name and ensure that the
    custom role is loaded.

    The custom roles have to be applied to a specific subscription ID, but
    the subscription ID applies to the entire credential, so will almost
    certainly be reused, so there's not much danger in hitting the 2k
    custom role limit.
    """
    known_roles = kv().get('charm.azure.roles', {})
    if role_name in known_roles:
        return known_roles[role_name]
    sub_id = kv().get('charm.azure.sub-id')
    role_file = Path('files/roles/{}.json'.format(role_name))
    role_data = json.loads(role_file.read_text())
    role_fullname = role_data['Name'].format(sub_id)
    scope = role_data['AssignableScopes'][0].format(sub_id)
    role_data['Name'] = role_fullname
    role_data['AssignableScopes'][0] = scope
    try:
        log('Ensuring role {}', role_fullname)
        _azure('role', 'definition', 'create',
               '--role-definition', json.dumps(role_data))
    except AlreadyExistsAzureError:
        pass
    known_roles[role_name] = role_fullname
    kv().set('charm.azure.roles', known_roles)
    return role_fullname


def _assign_role(request, role):
    if isinstance(role, StandardRole):
        role = role.value
    msi = _get_msi(request.vm_id)
    try:
        _azure('role', 'assignment', 'create',
               '--assignee-object-id', msi,
               '--resource-group', request.resource_group,
               '--role', role)
    except AlreadyExistsAzureError:
        pass
