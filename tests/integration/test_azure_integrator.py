import json

import pytest
import requests


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test, lb_charms):
    if {"azure-integrator", "lb-consumer"} & ops_test.model.applications.keys():
        return
    await ops_test.model.deploy(await ops_test.build_charm("."), trust=True)
    await ops_test.model.deploy(await ops_test.build_charm(lb_charms.lb_consumer))
    await ops_test.model.add_relation("azure-integrator", "lb-consumer")
    await ops_test.model.wait_for_idle(timeout=20*60)


async def test_lb_exists(ops_test):
    az = ops_test.model.applications["azure-integrator"]
    uuid_part = ops_test.model.info.uuid.split('-')[0]
    rg = "juju-{}-{}".format(ops_test.model_name, uuid_part)
    data = await az.units[0].run("az network lb list -g " + rg)
    assert data.results["Code"] == "0"
    lbs = json.loads(data.results["Stdout"])
    assert len(lbs) == 1


async def test_connectivity(ops_test):
    lb_consumer = ops_test.model.applications["lb-consumer"]
    lb_unit = lb_consumer.units[0]
    assert lb_unit.workload_status == "active"
    address = lb_unit.workload_status_message
    r = requests.get(f"http://{address}/")
    assert r.status_code == 200
    assert "nginx" in r.text.lower()


async def test_cleanup(ops_test, az_cli):
    az = ops_test.model.applications["azure-integrator"]
    await az.remove_relation("lb-consumers", "lb-consumer")
    await ops_test.model.wait_for_idle()
    uuid_part = ops_test.model.info.uuid.split('-')[0]
    rg = "juju-{}-{}".format(ops_test.model_name, uuid_part)

    lbs = await az_cli("network lb list -g " + rg)
    assert len(lbs) == 0
    public_ips = await az_cli("network public-ip list --query '[*].name' -g " + rg)
    public_ips = [ip for ip in public_ips if ip.startswith("integrator-")]
    assert len(public_ips) == 0
    nsg_rules = await az_cli(
        "network nsg rule list --query '[*].name' --nsg-name juju-internal-nsg -g " + rg
    )
    nsg_rules = [rule for rule in nsg_rules if rule.startswith("integrator-")]
    assert len(nsg_rules) == 0
