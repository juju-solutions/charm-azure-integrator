import json

import pytest

from pytest_operator import OperatorTest


@pytest.mark.lb_charms
class TestAzureIntegrator(OperatorTest):
    @pytest.mark.abort_on_fail
    async def test_00_build_and_deploy(self):
        if {"azure-integrator", "lb-consumer"} & self.model.applications.keys():
            return
        await self.model.deploy(await self.build_charm("."), trust=True)
        await self.model.deploy(await self.build_charm(self.lb_charms.lb_consumer))
        await self.model.add_relation("azure-integrator", "lb-consumer")
        await self.model.wait_for_idle()

    async def test_01_exists(self):
        az = self.model.applications["azure-integrator"]
        uuid_part = self.model.info.uuid.split('-')[0]
        rg = "juju-{}-{}".format(self.model_name, uuid_part)
        data = await az.units[0].run("az network lb list -g " + rg)
        assert data.results["Code"] == "0"
        lbs = json.loads(data.results["Stdout"])
        assert len(lbs) == 1

    async def test_02_cleanup(self):
        az = self.model.applications["azure-integrator"]
        await az.remove_relation("lb-consumers", "lb-consumer")
        await self.model.wait_for_idle()
        uuid_part = self.model.info.uuid.split('-')[0]
        rg = "juju-{}-{}".format(self.model_name, uuid_part)
        data = await az.units[0].run("az network lb list -g " + rg)
        assert data.results["Code"] == "0"
        lbs = json.loads(data.results["Stdout"])
        assert len(lbs) == 0
