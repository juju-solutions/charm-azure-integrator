import json
import os
import re
import subprocess
from base64 import b64decode
from enum import Enum
from math import ceil, floor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen, Request

import yaml

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


ENTITY_PREFIX = "charm.azure"
MODEL_UUID = os.environ["JUJU_MODEL_UUID"]
MAX_ROLE_NAME_LEN = 64
MAX_POLICY_NAME_LEN = 128
SUPPORTED_LB_PROTOS = ["udp", "tcp"]
SUPPORTED_LB_ALGS = ["Default", "SourceIP", "SourceIPProtocol"]
SUPPORTED_LB_HC_PROTOS = ["http", "https", "tcp"]


class StandardRole(Enum):
    NETWORK_MANAGER = "4d97b98b-1d4f-4787-a291-c67834d212e7"
    SECURITY_MANAGER = "e3d13bf0-dd5a-482e-ba6b-9b8433878d10"
    DNS_MANAGER = "befefa01-2a29-4197-83a8-272ff33ce314"
    OBJECT_STORE_READER = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
    OBJECT_STORE_MANAGER = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"


class LoadBalancerException(BaseException):
    def __init__(self, message):
        self.message = message
        super().__init__(message)


class LoadBalancerUnsupportedFeatureException(BaseException):
    def __init__(self, error_fields):
        self.error_fields = error_fields
        self.message = str(error_fields)
        super().__init__(self.message)


# When debugging hooks, for some reason HOME is set to /home/ubuntu, whereas
# during normal hook execution, it's /root. Set it here to be consistent.
os.environ["HOME"] = "/root"


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
    no_creds_msg = "missing credentials; set credentials config"
    config = hookenv.config()
    # try to use Juju's trust feature
    try:
        result = subprocess.run(
            ["credential-get"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        creds = yaml.load(result.stdout.decode("utf8"))
        creds_data = creds["credential"]["attributes"]
        login_cli(creds_data)
        return True
    except FileNotFoundError:
        pass  # juju trust not available
    except subprocess.CalledProcessError as e:
        if "permission denied" not in e.stderr.decode("utf8"):
            raise
        no_creds_msg = "missing credentials access; grant with: juju trust"

    # try credentials config
    if config["credentials"]:
        try:
            creds_data = b64decode(config["credentials"]).decode("utf8")
            login_cli(json.loads(creds_data))
            return True
        except Exception as ex:
            msg = "invalid value for credentials config"
            log_debug("{}: {}", msg, ex)
            status.blocked(msg)
            return False

    # no creds provided
    status.blocked(no_creds_msg)
    return False


def login_cli(creds_data):
    """
    Use the credentials to authenticate the Azure CLI.
    """
    app_id = creds_data["application-id"]
    app_pass = creds_data["application-password"]
    sub_id = creds_data["subscription-id"]
    tenant_id = _get_tenant_id(sub_id)
    try:
        log("Forcing logout of Azure CLI")
        _azure("logout")
    except AzureError:
        pass
    try:
        log("Logging in to Azure CLI")
        _azure(
            "login",
            "--service-principal",
            "-u",
            app_id,
            "-p",
            app_pass,
            "-t",
            tenant_id,
        )
        # cache the subscription ID for use in roles
        kv().set("charm.azure.sub-id", sub_id)
    except AzureError as e:
        # redact the credential info from the exception message
        stderr = re.sub(app_id, "<app-id>", e.args[0])
        stderr = re.sub(app_pass, "<app-pass>", stderr)
        stderr = re.sub(tenant_id, "<tenant-id>", stderr)
        # from None suppresses the previous exception from the stack trace
        raise AzureError(stderr) from None


def ensure_msi(request):
    msi = _get_msi(request.vm_id)
    if not msi:
        log("Enabling Managed Service Identity")
        result = _azure(
            "vm",
            "identity",
            "assign",
            "--name",
            request.vm_name,
            "--resource-group",
            request.resource_group,
        )
        vm_identities = kv().get("charm.azure.vm-identities", {})
        msi = vm_identities[request.vm_id] = result["systemAssignedIdentity"]
        kv().set("charm.azure.vm-identities", vm_identities)
    log("Instance MSI is: {}", msi)


def send_additional_metadata(request):
    """
    Get additional info about the requesting instance via the API that isn't
    available from the metadata server.
    """
    run_config = hookenv.config() or {}
    res_grp = _azure("group", "show", "--name", request.resource_group)
    # hard-code most of these because with Juju, they're always the same
    # and the queries required to look them up are a PITA
    request.send_additional_metadata(
        resource_group_location=res_grp["location"],
        vnet_name=run_config.get("vnetName")
        if run_config.get("vnetName")
        else "juju-internal-network",
        vnet_resource_group=run_config.get("vnetResourceGroup")
        if run_config.get("vnetResourceGroup")
        else request.resource_group,
        subnet_name=run_config.get("subnetName")
        if run_config.get("subnetName")
        else "juju-internal-subnet",
        security_group_name=run_config.get("vnetSecurityGroup")
        if run_config.get("vnetSecurityGroup")
        else "juju-internal-nsg",
    )


def tag_instance(request):
    """
    Tag the given instance with the given tags.
    """
    log("Tagging instance with: {}", request.instance_tags)
    _azure(
        "vm",
        "update",
        "--name",
        request.vm_name,
        "--resource-group",
        request.resource_group,
        "--set",
        *[
            "tags.{}={}".format(tag, value)
            for tag, value in request.instance_tags.items()
        ],
    )


def enable_instance_inspection(request):
    """
    Enable instance inspection access for the given application.
    """
    log("Enabling instance inspection")
    _assign_role(request, _get_role("vm-reader"))


def enable_network_management(request):
    """
    Enable network management for the given application.
    """
    log("Enabling network management")
    _assign_role(request, StandardRole.NETWORK_MANAGER)


def _lb_name(request):
    """
    Normalize and return the name of a LB request.
    """
    return "integrator-{}-{}".format(request.name, request.id)


def _lb_algo(request):
    """
    Choose a supported algorithm for the request.
    """
    if not request.algorithm:
        return "Default"
    for supported in SUPPORTED_LB_ALGS:
        if supported in request.algorithm:
            return supported
    return None


def _validate_loadbalancer_request(request):
    """
    Validate the incoming request.

    :return: None
    """
    error_fields = {}
    if request.protocol.value not in SUPPORTED_LB_PROTOS:
        error_fields["protocol"] = "Must be one of: {}".format(
            ", ".join(SUPPORTED_LB_PROTOS)
        )

    if not _lb_algo(request):
        error_fields["algorithm"] = "Must be one of: {}".format(
            ", ".join(SUPPORTED_LB_ALGS)
        )

    if request.tls_termination:
        error_fields["tls_termination"] = "Not yet supported"

    for i, hc in enumerate(request.health_checks):
        if hc.protocol.value not in SUPPORTED_LB_HC_PROTOS:
            error_fields["hc[{}].protocol".format(i)] = "Must be one of: {}".format(
                ", ".join(SUPPORTED_LB_PROTOS)
            )
        if hc.path and hc.protocol.value not in ("http", "https"):
            error_fields["hc[{}].path".format(i)] = "Only valid with http(s) protocol"

    if error_fields:
        hookenv.log("Unsupported features: {}".format(error_fields), hookenv.ERROR)
        raise LoadBalancerUnsupportedFeatureException(error_fields)


def create_loadbalancer(request):
    """
    Create an Azure LoadBalancer.

    :return: String address of load balancer
    """
    _validate_loadbalancer_request(request)

    resource_group = _get_resource_group()

    model_tag = "juju-model-uuid=" + MODEL_UUID

    lb_name = _lb_name(request)
    lb_pip_name = lb_name + "-public-ip"
    lb_pool_name = lb_name + "-pool"

    lb_create_args = [
        "lb",
        "create",
        "--name",
        lb_name,
        "--resource-group",
        resource_group,
        "--backend-pool-name",
        lb_pool_name,
        "--tags",
        model_tag,
    ]

    if request.public:
        lb_create_args += [
            "--public-ip-address",
            lb_pip_name,
        ]
    else:
        lb_create_args += [
            "--vnet-name",
            "juju-internal-network",  # TODO find this.
            "--subnet",
            "juju-internal-subnet",  # TODO find this.
        ]

    lb_created = _azure("network", *lb_create_args)

    if request.public:
        _azure(
            "network",
            "public-ip",
            "create",
            "--name",
            lb_pip_name,
            "--resource-group",
            resource_group,
            "--tags",
            model_tag,
        )

    backend_args = []
    for i, backend in enumerate(request.backends):
        backend_args += [
            "--backend-address",
            "name=addr{}".format(i),
            "ip-address={}".format(backend),
        ]
    _azure(
        "network",
        "lb",
        "address-pool",
        "create",
        "--name",
        lb_pool_name,
        "--resource-group",
        resource_group,
        "--lb-name",
        lb_name,
        *backend_args,
    )

    for front, back in request.port_mapping.items():
        _azure(
            "network",
            "lb",
            "rule",
            "create",
            "--name",
            "{}-rule-{}-{}".format(lb_name, front, back),
            "--resource-group",
            resource_group,
            "--lb-name",
            lb_name,
            "--frontend-port",
            front,
            "--backend-port",
            back,
            "--protocol",
            request.protocol.value.capitalize(),
        )

    for i, health_check in enumerate(request.health_checks):
        lb_probe_create_args = [
            "lb",
            "probe",
            "create",
            "--name",
            "{}-probe-{}".format(lb_name, i),
            "--resource-group",
            resource_group,
            "--lb-name",
            lb_name,
            "--protocol",
            health_check.protocol.value.capitalize(),
            "--port",
            health_check.port,
            "--interval",
            health_check.interval,
            "--threshold",
            health_check.retries,
        ]

        if health_check.path:
            lb_probe_create_args += ["--path", health_check.path]

        _azure("network", *lb_probe_create_args)

    if request.public:
        ip = lb_created["loadBalancer"]["frontendIPConfigurations"][0]["properties"][
            "publicIPAddress"
        ]
        hookenv.log("LB created with public IP {}".format(ip), hookenv.INFO)
        return ip
    else:
        ip = lb_created["loadBalancer"]["frontendIPConfigurations"][0]["properties"][
            "privateIPAddress"
        ]
        hookenv.log("LB created with private IP {}".format(ip), hookenv.INFO)
        return ip


def remove_loadbalancer(request):
    """
    Remove a single load balancer.

    :return: None
    """
    resource_group = _get_resource_group()
    # NB: Deleting the LB itself deletes any resources directly associated with it.
    lb_name = _lb_name(request)
    # However, the public IP isn't directly associated with the LB.
    lb_pip_name = lb_name + "-public-ip"
    commands = [
        (
            "network",
            "lb",
            "delete",
            "--name",
            lb_name,
            "--resource-group",
            resource_group,
        ),
        (
            "network",
            "public-ip",
            "delete",
            "--name",
            lb_pip_name,
            "--resource-group",
            resource_group,
        ),
    ]
    for command in commands:
        try:
            _azure(*command)
        except DoesNotExistAzureError:
            pass


def enable_loadbalancer_management(request):
    """
    Enable load balancer management for the given application.
    """
    log("Enabling load balancer management")
    _assign_role(request, _get_role("lb-manager"))

    rg = (
        hookenv.config("vnetResourceGroup")
        if hookenv.config("vnetResourceGroup")
        else request.resource_group
    )

    # In this case, we need to have permissions on both VM and network RGs.
    if rg != request.resource_group:
        _assign_role(request, _get_role("lb-manager"), rg)


def enable_security_management(request):
    """
    Enable security management for the given application.
    """
    log("Enabling security management")
    _assign_role(request, StandardRole.SECURITY_MANAGER)


def enable_block_storage_management(request):
    """
    Enable block storage (disk) management for the given application.
    """
    log("Enabling block storage management")
    _assign_role(request, _get_role("disk-manager"))


def enable_dns_management(request):
    """
    Enable DNS management for the given application.
    """
    log("Enabling DNS management")
    _assign_role(request, StandardRole.DNS_MANAGER)


def enable_object_storage_access(request):
    """
    Enable object storage read-only access for the given application.
    """
    log("Enabling object storage read")
    _assign_role(request, StandardRole.OBJECT_STORE_READER)


def enable_object_storage_management(request):
    """
    Enable object storage management for the given application.
    """
    log("Enabling object store management")
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
    sub_id = kv().get("charm.azure.sub-id")
    known_roles = {}
    for role_file in Path("files/roles/").glob("*.json"):
        role_name = role_file.stem
        role_data = json.loads(role_file.read_text())
        role_fullname = role_data["Name"].format(sub_id)
        scope = role_data["AssignableScopes"][0].format(sub_id)
        role_data["Name"] = role_fullname
        role_data["AssignableScopes"][0] = scope
        try:
            # assume already exists, so try updating first
            _azure(
                "role",
                "definition",
                "update",
                "--role-definition",
                json.dumps(role_data),
            )
            log("Updated existing role {}", role_fullname)
        except DoesNotExistAzureError:
            # doesn't exist, so create
            _azure(
                "role",
                "definition",
                "create",
                "--role-definition",
                json.dumps(role_data),
            )
            log("Created new role {}", role_fullname)
        known_roles[role_name] = role_fullname
    kv().set("charm.azure.roles", known_roles)


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
        if "already exists" in message:
            return AlreadyExistsAzureError(message)
        if "Please provide" in message and "an existing" in message:
            return DoesNotExistAzureError(message)
        if "No definition was found" in message:
            return DoesNotExistAzureError(message)
        if "could not be found" in message:
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


def _elide(s, max_len, ellipsis="..."):
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


def _azure(cmd, *args, return_stderr=False):
    """
    Call the azure-cli tool.
    """
    cmd = ["az", cmd]
    cmd.extend(str(arg) for arg in args)
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = result.stdout.decode("utf8").strip()
    stderr = result.stderr.decode("utf8").strip()
    if result.returncode != 0:
        raise AzureError.get(stderr)
    if return_stderr:
        return stderr
    if stdout:
        stdout = json.loads(stdout)
    return stdout


def _get_nic_from_ip(ip, resource_group):
    """
    Loop over the NICs present and pull out the one
    that matches the IP.

    :param ip: String ip address to match
    :param resource_group: String resource group to filter by
    """
    nics = json.loads(
        _azure("network", "nic", "list", "--resource-group", resource_group)
    )

    for nic in nics:
        for conf in nic.get("ipConfigurations"):
            if conf.get("privateIpAddress") == ip:
                return conf.get("id")


def _get_tenant_id(subscription_id):
    """
    Translate the subscription ID into a tenant ID by making an unauthorized
    request to the API and extracting the tenant ID from the WWW-Authenticate
    header in the error response.
    """
    url = (
        "https://management.azure.com/subscriptions/"
        "{}?api-version=2018-03-01-01.6.1".format(subscription_id)
    )
    try:
        urlopen(url)
        log_err('Error getting tenant ID: did not get "unauthorized" response')
        return None
    except HTTPError as e:
        if "WWW-Authenticate" not in e.headers:
            log_err("Error getting tenant ID: missing WWW-Authenticate header")
            return None
        www_auth = e.headers["WWW-Authenticate"]
        match = re.search(r'authorization_uri="[^"]*/([^/"]*)"', www_auth)
        if not match:
            log_err("Error getting tenant ID: unable to find in {}", www_auth)
            return None
        return match.group(1)


def _get_msi(vm_id):
    """
    Get the Managed System Identity for the VM.
    """
    vm_identities = kv().get("charm.azure.vm-identities", {})
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
    known_roles = kv().get("charm.azure.roles", {})
    if role_name in known_roles:
        return known_roles[role_name]
    sub_id = kv().get("charm.azure.sub-id")
    role_file = Path("files/roles/{}.json".format(role_name))
    role_data = json.loads(role_file.read_text())
    role_fullname = role_data["Name"].format(sub_id)
    scope = role_data["AssignableScopes"][0].format(sub_id)
    role_data["Name"] = role_fullname
    role_data["AssignableScopes"][0] = scope
    try:
        log("Ensuring role {}", role_fullname)
        _azure(
            "role", "definition", "create", "--role-definition", json.dumps(role_data)
        )
    except AlreadyExistsAzureError:
        pass
    known_roles[role_name] = role_fullname
    kv().set("charm.azure.roles", known_roles)
    return role_fullname


def _get_resource_group():
    """
    Filter resource group from metadata.
    """
    return _get_metadata()["compute"]["resourceGroupName"]


def _get_metadata():
    """
    Return an object populated from the metadata server.
    """
    cache = kv().get("charm.azure.instance.metadata", None)
    if cache:
        return cache
    else:
        r = Request(
            "http://169.254.169.254/metadata/instance?api-version=2017-12-01",
            headers={"Metadata": "true"},
        )
        with urlopen(r) as f:
            md = json.loads(f.read(2048).decode("utf8").strip())
            kv().set("charm.azure.instance.metadata", md)
            return md


def _assign_role(request, role, resource_group=None):
    if isinstance(role, StandardRole):
        role = role.value
    msi = _get_msi(request.vm_id)
    rg = request.resource_group
    if resource_group is not None:
        rg = resource_group
    try:
        _azure(
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            msi,
            "--resource-group",
            rg,
            "--role",
            role,
        )
    except AlreadyExistsAzureError:
        pass
