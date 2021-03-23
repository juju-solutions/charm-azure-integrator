import json
from functools import partial

import pytest


@pytest.fixture
def az_cli(ops_test):
    unit = ops_test.model.applications["azure-integrator"].units[0]

    async def az_cli_impl(args):
        data = await unit.run("az " + args)
        assert data.results["Code"] == "0"
        return json.loads(data.results["Stdout"])

    return az_cli_impl


@pytest.fixture
def rg_name(ops_test):
    uuid_part = ops_test.model.info.uuid.split("-")[0]
    return "juju-{}-{}".format(ops_test.model_name, uuid_part)


@pytest.fixture
def _factory(az_cli, rg_name):
    return lambda cmd: partial(az_cli, cmd.format(rg_name=rg_name))


@pytest.fixture
def list_lbs(_factory):
    return _factory(
        "network lb list -g {rg_name} "
        "--query '[?starts_with(name, `integrator-`)].name'"
    )


@pytest.fixture
def list_public_ips(_factory):
    return _factory(
        "network public-ip list -g {rg_name} "
        "--query '[?starts_with(name, `integrator-`)].name'"
    )


@pytest.fixture
def list_nsg_rules(_factory):
    return _factory(
        "network nsg rule list -g {rg_name} --nsg-name juju-internal-nsg "
        "--query '[?starts_with(name, `integrator-`)].name'"
    )
