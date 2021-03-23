import logging

import pytest
import requests


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test, lb_charms):
    if {"azure-integrator", "lb-consumer"} & ops_test.model.applications.keys():
        # Allow for re-running a previous test or using an existing deploy.
        pytest.skip("Already deployed")
    await ops_test.model.deploy(await ops_test.build_charm("."), trust=True)
    await ops_test.model.deploy(await ops_test.build_charm(lb_charms.lb_consumer))
    await ops_test.model.wait_for_idle(timeout=20 * 60)


@pytest.mark.parametrize("visibility", ["public", "internal"])
async def test_lb(ops_test, list_lbs, list_public_ips, list_nsg_rules, visibility):
    lb_consumer = ops_test.model.applications["lb-consumer"]
    lb_unit = lb_consumer.units[0]
    az_unit = ops_test.model.applications["azure-integrator"].units[0]
    # Sanity check
    assert await list_lbs() == []
    assert await list_public_ips() == []
    assert await list_nsg_rules() == []
    assert lb_unit.workload_status == "waiting"
    log.info(f"Creating {visibility} LB")
    await lb_consumer.set_config(
        {"public": "true" if visibility == "public" else "false"}
    )
    await ops_test.model.add_relation("azure-integrator", "lb-consumer")
    log.info("Waiting for LB")
    await ops_test.model.wait_for_idle()
    is_failed = False
    try:
        log.info("Verifying LB components")
        assert await list_lbs() != []
        if visibility == "public":
            assert await list_public_ips() != []
            assert await list_nsg_rules() != []
        else:
            assert await list_public_ips() == []
            assert await list_nsg_rules() == []
        assert lb_unit.workload_status == "active"
        address = lb_unit.workload_status_message
        lb_url = f"http://{address}/"
        if visibility == "public":
            log.info(f"Confirming external access to {lb_url}")
            r = requests.get(lb_url)
            assert r.status_code == 200
            assert "nginx" in r.text.lower()
        units = [az_unit]
        if visibility == "public":
            # Backends can never reach their own internal LBs, so self-connectivity can
            # only be validated for a public LB. See bullet #3 on:
            # https://docs.microsoft.com/en-us/azure/load-balancer/components#limitations
            units.append(lb_unit)
        for unit in units:
            log.info(f"Confirming access from {unit.name} to {lb_url}")
            data = await unit.run(f"curl -i '{lb_url}'")
            output = data.results.get("Stdout", data.results.get("Stderr", ""))
            assert "nginx" in output
    except Exception as e:
        is_failed = True
        log.error(f"Failed: {e}")
        raise
    finally:
        log.info("Cleaning up LB")
        await lb_consumer.remove_relation("lb-provider", "azure-integrator")
        await ops_test.model.wait_for_idle()
        for check, dsc in [
            (await list_lbs(), "LBs"),
            (await list_public_ips(), "public IPs"),
            (await list_nsg_rules(), "NSG rules"),
        ]:
            msg = f"Failed to clean up {dsc}: {check}"
            if is_failed:
                if check != []:
                    # Only log failed cleanup, rather than assert, so as to not
                    # mask other failure.
                    log.error(msg)
            else:
                assert check == [], msg
