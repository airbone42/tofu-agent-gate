import unittest

from tofu_agent_gate import plan as planlib
from tofu_agent_gate.policy import Policy, PolicyError, classify

from planbuilder import ZONES, dns_obj, plan, policy_obj, rc

POLICY = {
    "version": 1,
    "vars": {
        "auto_zones": [ZONES["iot"], ZONES["isolated"]],
        "zone_mgmt": ZONES["mgmt"],
    },
    "limits": {"max_changes": 3, "allow_delete": ["unifi_dns_record"], "allow_replace": []},
    "providers": {
        "allowed": ["registry.opentofu.org/ubiquiti-community/unifi"],
        "forbidden_arguments": ["api_url", "api_key", "allow_insecure"],
    },
    "forbidden": [
        {"type": "unifi_setting"},
        {"type": "unifi_port_forward"},
        {"references": ["$zone_mgmt"]},
        {"address": "unifi_firewall_policy.protected_*"},
    ],
    "rules": [
        {"level": "auto", "type": "unifi_dns_record"},
        {
            "level": "auto",
            "type": "unifi_firewall_policy",
            "actions": ["create", "update"],
            "where": {
                "source.zone_id": {"in": "$auto_zones"},
                "destination.zone_id": {"in": "$auto_zones"},
            },
        },
    ],
    "default": "approval",
}


def pol(**over) -> Policy:
    d = dict(POLICY)
    d.update(over)
    return Policy.from_dict(d)


class ClassifyTest(unittest.TestCase):
    def test_dns_create_is_auto(self):
        p = plan(rc("unifi_dns_record.a", ["create"], None, dns_obj(None, "host-1.example")))
        d = classify(p, pol())
        self.assertEqual(d.level, "auto", d.to_dict())

    def test_policy_between_auto_zones_is_auto(self):
        before = policy_obj("p1", "iot to isolated", "iot", "isolated")
        after = dict(before, protocol="tcp")
        d = classify(plan(rc("unifi_firewall_policy.x", ["update"], before, after)), pol())
        self.assertEqual(d.level, "auto")

    def test_policy_moving_out_of_auto_zones_needs_approval(self):
        before = policy_obj("p1", "iot to isolated", "iot", "isolated")
        after = policy_obj("p1", "iot to isolated", "iot", "lan")
        d = classify(plan(rc("unifi_firewall_policy.x", ["update"], before, after)), pol())
        self.assertEqual(d.level, "approval")

    def test_policy_moving_into_auto_zones_needs_approval(self):
        # Vorher lan, nachher iot: beide Seiten müssen passen.
        before = policy_obj("p1", "x", "lan", "isolated")
        after = policy_obj("p1", "x", "iot", "isolated")
        d = classify(plan(rc("unifi_firewall_policy.x", ["update"], before, after)), pol())
        self.assertEqual(d.level, "approval")

    def test_unknown_zone_is_not_auto(self):
        after = policy_obj(None, "x", "iot", "isolated")
        p = plan(rc("unifi_firewall_policy.x", ["create"], None, after,
                    after_unknown={"source": {"zone_id": True}}))
        self.assertEqual(classify(p, pol()).level, "approval")

    def test_other_policy_needs_approval(self):
        after = policy_obj(None, "lan to guest", "lan", "guest")
        d = classify(plan(rc("unifi_firewall_policy.x", ["create"], None, after)), pol())
        self.assertEqual(d.level, "approval")

    def test_forbidden_type_rejected(self):
        p = plan(rc("unifi_setting.mgmt", ["update"], {"x": 1}, {"x": 2}))
        d = classify(p, pol())
        self.assertEqual(d.level, "reject")
        self.assertIn("forbidden", d.reasons[0])

    def test_forbidden_reference_rejected_even_for_auto_type(self):
        after = dns_obj(None, "x.example", value=ZONES["mgmt"])
        self.assertEqual(classify(plan(rc("unifi_dns_record.a", ["create"], None, after)), pol()).level, "reject")

    def test_forbidden_reference_in_before_rejected(self):
        before = policy_obj("p1", "x", "mgmt", "iot")
        after = policy_obj("p1", "x", "iot", "iot")
        p = plan(rc("unifi_firewall_policy.x", ["update"], before, after))
        self.assertEqual(classify(p, pol()).level, "reject")

    def test_forbidden_address_glob(self):
        after = policy_obj("p1", "x", "iot", "iot")
        p = plan(rc("unifi_firewall_policy.protected_core", ["update"], after, dict(after, enabled=False)))
        self.assertEqual(classify(p, pol()).level, "reject")

    def test_import_of_forbidden_object_rejected(self):
        obj = policy_obj("p9", "mgmt in", "lan", "mgmt")
        p = plan(rc("unifi_firewall_policy.m", ["no-op"], obj, obj, importing="p9"))
        self.assertEqual(classify(p, pol()).level, "reject")

    def test_delete_only_for_allowed_types(self):
        obj = policy_obj("p1", "x", "iot", "iot")
        d = classify(plan(rc("unifi_firewall_policy.x", ["delete"], obj, None)), pol())
        self.assertEqual(d.level, "reject")
        d = classify(plan(rc("unifi_dns_record.a", ["delete"], dns_obj("r1", "a.example"), None)), pol())
        self.assertEqual(d.level, "auto")

    def test_replace_needs_explicit_permission(self):
        a = dns_obj("r1", "a.example")
        p = plan(rc("unifi_dns_record.a", ["delete", "create"], a, dict(a, name="b.example")))
        self.assertEqual(classify(p, pol()).level, "reject")
        p2 = pol(limits={"max_changes": 3, "allow_delete": ["unifi_dns_record"], "allow_replace": ["unifi_dns_record"]})
        self.assertEqual(classify(p, p2).level, "auto")

    def test_max_changes(self):
        chs = [rc(f"unifi_dns_record.r{i}", ["create"], None, dns_obj(None, f"h{i}.example")) for i in range(4)]
        d = classify(plan(*chs), pol())
        self.assertEqual(d.level, "reject")
        self.assertIn("4 Änderungen", d.reasons[0])

    def test_strictest_level_wins(self):
        p = plan(
            rc("unifi_dns_record.a", ["create"], None, dns_obj(None, "a.example")),
            rc("unifi_firewall_policy.x", ["create"], None, policy_obj(None, "x", "lan", "guest")),
        )
        self.assertEqual(classify(p, pol()).level, "approval")

    def test_noop_and_read_ignored(self):
        obj = dns_obj("r1", "a.example")
        p = plan(
            rc("unifi_dns_record.a", ["no-op"], obj, obj),
            rc("data.unifi_firewall_zone.z", ["read"], None, {}, rtype="unifi_firewall_zone", mode="data"),
        )
        d = classify(p, pol())
        self.assertEqual(d.level, "auto")
        self.assertEqual(d.items, [])

    def test_provider_argument_in_config_rejected(self):
        p = plan(rc("unifi_dns_record.a", ["create"], None, dns_obj(None, "a.example")),
                 provider_expressions={"api_url": {"constant_value": "https://evil.example"}})
        self.assertEqual(classify(p, pol()).level, "reject")

    def test_foreign_provider_rejected(self):
        p = plan()
        p["configuration"]["provider_config"]["external"] = {"full_name": "registry.opentofu.org/hashicorp/external"}
        self.assertEqual(classify(p, pol()).level, "reject")

    def test_provisioner_rejected(self):
        self.assertEqual(classify(plan(provisioners=True), pol()).level, "reject")

    def test_errored_plan_rejected(self):
        self.assertEqual(classify(plan(errored=True), pol()).level, "reject")

    def test_data_mode_change_rejected(self):
        p = plan(rc("unifi_dns_record.a", ["create"], None, dns_obj(None, "a.example"), mode="weird"))
        self.assertEqual(classify(p, pol()).level, "reject")

    def test_allowed_types(self):
        p2 = pol(limits={"max_changes": 3, "allowed_types": ["unifi_dns_record"]})
        p = plan(rc("unifi_network.n", ["create"], None, {"name": "n"}))
        self.assertEqual(classify(p, p2).level, "reject")


class RollbackTest(unittest.TestCase):
    def test_rollback_ignores_limits_and_approval(self):
        chs = [rc(f"unifi_firewall_policy.p{i}", ["delete"], policy_obj(f"p{i}", "x", "lan", "guest"), None)
               for i in range(5)]
        self.assertEqual(classify(plan(*chs), pol(), rollback=True).level, "auto")

    def test_rollback_still_checks_forbidden(self):
        p = plan(rc("unifi_setting.mgmt", ["update"], {"x": 1}, {"x": 2}))
        self.assertEqual(classify(p, pol(), rollback=True).level, "reject")


class PolicyLoadTest(unittest.TestCase):
    def test_unknown_variable(self):
        with self.assertRaises(PolicyError):
            pol(forbidden=[{"references": ["$nope"]}])

    def test_unknown_key(self):
        with self.assertRaises(PolicyError):
            pol(rules=[{"level": "auto", "typ": "x"}])

    def test_unknown_level(self):
        with self.assertRaises(PolicyError):
            pol(default="yolo")

    def test_bad_condition(self):
        with self.assertRaises(PolicyError):
            pol(rules=[{"level": "auto", "where": {"a": {"contains": 1}}}])

    def test_version_required(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": []})


class SummaryTest(unittest.TestCase):
    def test_summary_masks_sensitive(self):
        before = {"name": "wlan", "passphrase": "old-secret"}
        after = {"name": "wlan", "passphrase": "new-secret"}
        c = rc("unifi_wlan.w", ["update"], before, after, after_sensitive={"passphrase": True})
        c["change"]["before_sensitive"] = {"passphrase": True}
        text = planlib.summarize(planlib.changes(plan(c)))
        self.assertNotIn("secret", text)
        self.assertIn("<sensitive>", text)

    def test_summary_lists_changes(self):
        before = policy_obj("p1", "iot to isolated", "iot", "isolated")
        text = planlib.summarize(planlib.changes(plan(
            rc("unifi_firewall_policy.x", ["update"], before, dict(before, protocol="tcp")))))
        self.assertIn("update unifi_firewall_policy.x (iot to isolated)", text)
        self.assertIn("protocol: all -> tcp", text)


if __name__ == "__main__":
    unittest.main()
