import json
import pytest


@pytest.fixture
def az_cli(ops_test):
    unit = ops_test.model.applications["azure-integrator"].units[0]

    async def az_cli_impl(args):
        data = await unit.run("az " + args)
        assert data.results["Code"] == "0"
        return json.loads(data.results["Stdout"])

    return az_cli_impl
