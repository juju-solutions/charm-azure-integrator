import pytest
import requests


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test, lb_charms):
    if {"azure-integrator", "lb-consumer"} & ops_test.model.applications.keys():
        # Allow for re-running a previous test or using an existing deploy.
        pytest.skip("Already deployed")
    await ops_test.model.deploy(await ops_test.build_charm("."), trust=True)
    await ops_test.model.deploy(await ops_test.build_charm(lb_charms.lb_consumer))
    await ops_test.model.wait_for_idle(timeout=20*60)


async def test_public(ops_test, list_lbs, list_public_ips, list_nsg_rules):
    lb_consumer = ops_test.model.applications["lb-consumer"]
    lb_unit = lb_consumer.units[0]
    # Sanity check
    assert await list_lbs() == []
    assert await list_public_ips() == []
    assert await list_nsg_rules() == []
    assert lb_unit.workload_status == "waiting"
    # Create public LB
    await lb_consumer.set_config({"public": "true"})
    await ops_test.model.add_relation("azure-integrator", "lb-consumer")
    await ops_test.model.wait_for_idle()
    try:
        try:
            # Check public LB creation
            assert await list_lbs() != []
            assert await list_public_ips() != []
            assert await list_nsg_rules() != []
            assert lb_unit.workload_status == "active"
            address = lb_unit.workload_status_message
            r = requests.get(f"http://{address}/")
            assert r.status_code == 200
            assert "nginx" in r.text.lower()
        finally:
            # Cleanup
            await lb_consumer.remove_relation("lb-provider", "azure-integrator")
            await ops_test.model.wait_for_idle()
    except Exception:
        raise
    else:
        # Check cleanup
        assert await list_lbs() == []
        assert await list_public_ips() == []
        assert await list_nsg_rules() == []


async def test_private(ops_test, list_lbs, list_public_ips, list_nsg_rules):
    lb_consumer = ops_test.model.applications["lb-consumer"]
    lb_unit = lb_consumer.units[0]
    az_unit = ops_test.model.applications["azure-integrator"].units[0]
    # Sanity check
    assert await list_lbs() == []
    assert await list_public_ips() == []
    assert await list_nsg_rules() == []
    assert lb_unit.workload_status == "waiting"
    # Create private LB
    await lb_consumer.set_config({"public": "false"})
    await ops_test.model.add_relation("azure-integrator", "lb-consumer")
    await ops_test.model.wait_for_idle()
    try:
        try:
            # Check private LB creation
            assert await list_lbs() != []
            assert await list_public_ips() == []
            assert await list_nsg_rules() == []
            assert lb_unit.workload_status == "active"
            address = lb_unit.workload_status_message
            data = await az_unit.run(f"curl -i 'http://{address}/'")
            assert "nginx" in data.results["Stdout"]
        finally:
            # Cleanup
            await lb_consumer.remove_relation("lb-provider", "azure-integrator")
            await ops_test.model.wait_for_idle()
    except Exception:
        raise
    else:
        # Check cleanup
        assert await list_lbs() == []
        assert await list_public_ips() == []
        assert await list_nsg_rules() == []
