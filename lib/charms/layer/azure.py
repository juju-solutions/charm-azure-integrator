import json
import os
import re
import subprocess
from base64 import b64decode
from math import ceil, floor
from urllib.error import HTTPError
from urllib.request import urlopen

import yaml

from charmhelpers.core import hookenv

from charms.layer import status


ENTITY_PREFIX = 'charm.azure'
MODEL_UUID = os.environ['JUJU_MODEL_UUID']
MAX_ROLE_NAME_LEN = 64
MAX_POLICY_NAME_LEN = 128

# When debugging hooks, for some reason HOME is set to /home/ubuntu, whereas
# during normal hook execution, it's /root. Set it here to be consistent.
os.environ['HOME'] = '/root'


def log(msg, *args):
    hookenv.log(msg.format(*args), hookenv.INFO)


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
            login_cli(creds_data)
            return True
        except Exception:
            status.blocked('invalid value for credentials config')
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
        _azure('logout')
    except AzureError:
        pass
    try:
        _azure('login',
               '--service-principal',
               '-u', app_id,
               '-p', app_pass,
               '-t', tenant_id)
    except AzureError as e:
        # redact the credential info from the exception message
        stderr = re.sub(app_id, '<app-id>', e.args[0])
        stderr = re.sub(app_pass, '<app-pass>', stderr)
        stderr = re.sub(tenant_id, '<tenant-id>', stderr)
        # from None suppresses the previous exception from the stack trace
        raise AzureError(stderr) from None


def tag_instance(vm_name, resource_group, tags):
    """
    Tag the given instance with the given tags.
    """
    log('Tagging instance {} in {} with: {}', vm_name, resource_group, tags)
    _azure('vm', 'update',
           '--name', vm_name,
           '--resource-group', resource_group,
           '--set', *['tags.{}={}'.format(tag, value)
                      for tag, value in tags.items()])


def enable_instance_inspection(model_uuid, application_name):
    """
    Enable instance inspection access for the given application.
    """
    log('Enabling instance inspection for {}', application_name)


def enable_network_management(model_uuid, application_name):
    """
    Enable network management for the given application.
    """
    log('Enabling network management for {}', application_name)


def enable_security_management(model_uuid, application_name):
    """
    Enable security management for the given application.
    """
    log('Enabling security management for {}', application_name)


def enable_block_storage_management(model_uuid, application_name):
    """
    Enable block storage (disk) management for the given application.
    """
    log('Enabling block storage management for {}', application_name)


def enable_dns_management(model_uuid, application_name):
    """
    Enable DNS management for the given application.
    """
    log('Enabling DNS management for {}', application_name)


def enable_object_storage_access(model_uuid, application_name):
    """
    Enable object storage read-only access for the given application.
    """
    log('Enabling object storage read for {}', application_name)


def enable_object_storage_management(model_uuid, application_name):
    """
    Enable object storage management for the given application.
    """
    log('Enabling object store management for {}', application_name)


def cleanup():
    """
    Perform cleanup.
    """
    pass


# Internal helpers


class AzureError(Exception):
    """
    Exception class representing an error returned from the azure-cli tool.
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
        raise AzureError(stderr)
    if return_stderr:
        return stderr
    if stdout:
        stdout = json.loads(stdout)
    return stdout
