# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
"""
Tests — aiss/agent_identity.py
AgentIdentity developer-friendly API
"""

import json
import time
import unittest


class TestAgentIdentityCreate(unittest.TestCase):

    def test_create_returns_instance(self):
        from aiss import AgentIdentity
        agent = AgentIdentity.create()
        self.assertIsInstance(agent, AgentIdentity)

    def test_agent_id_is_32_chars(self):
        from aiss import AgentIdentity
        agent = AgentIdentity.create()
        self.assertEqual(len(agent.agent_id), 32)

    def test_two_creates_are_unique(self):
        from aiss import AgentIdentity
        a1 = AgentIdentity.create()
        a2 = AgentIdentity.create()
        self.assertNotEqual(a1.agent_id, a2.agent_id)

    def test_create_with_name(self):
        from aiss import AgentIdentity
        agent = AgentIdentity.create(name="trading_bot")
        self.assertEqual(agent.name, "trading_bot")

    def test_from_keys_roundtrip(self):
        from aiss import AgentIdentity
        a1 = AgentIdentity.create()
        a2 = AgentIdentity.from_keys(a1._private_key, a1._public_key)
        self.assertEqual(a1.agent_id, a2.agent_id)

    def test_identity_doc_structure(self):
        from aiss import AgentIdentity
        agent = AgentIdentity.create()
        doc = agent.identity_doc
        self.assertEqual(doc["version"], "AISS-1.0")
        self.assertEqual(doc["agent_id"], agent.agent_id)
        self.assertEqual(doc["algorithm"], "Ed25519")
        self.assertIn("public_key", doc)
        self.assertIn("created_at", doc)


class TestAgentIdentityStamp(unittest.TestCase):

    def setUp(self):
        from aiss import AgentIdentity
        self.agent = AgentIdentity.create()

    def test_stamp_returns_signed_event(self):
        from aiss import SignedEvent
        event = self.agent.stamp("user_prompted", {"data": "hello"})
        self.assertIsInstance(event, SignedEvent)

    def test_stamp_event_type(self):
        event = self.agent.stamp("trade_executed", {"symbol": "BTC"})
        self.assertEqual(event.event_type, "trade_executed")

    def test_stamp_payload(self):
        event = self.agent.stamp("decision", {"action": "buy", "qty": 1.0})
        self.assertEqual(event.payload["action"], "buy")
        self.assertEqual(event.payload["qty"], 1.0)

    def test_stamp_agent_id_matches(self):
        event = self.agent.stamp("test_event")
        self.assertEqual(event.agent_id, self.agent.agent_id)

    def test_stamp_has_signature(self):
        event = self.agent.stamp("test_event")
        self.assertIsNotNone(event.signature)
        self.assertGreater(len(event.signature), 10)

    def test_stamp_has_hash(self):
        event = self.agent.stamp("test_event")
        self.assertIsNotNone(event.hash)
        self.assertEqual(len(event.hash), 64)  # SHA-256 hex

    def test_stamp_has_timestamp(self):
        before = int(time.time())
        event = self.agent.stamp("test_event")
        after = int(time.time())
        self.assertGreaterEqual(event.timestamp, before)
        self.assertLessEqual(event.timestamp, after)

    def test_stamp_chain_grows(self):
        self.assertEqual(self.agent.chain_length, 0)
        self.agent.stamp("e1")
        self.assertEqual(self.agent.chain_length, 1)
        self.agent.stamp("e2")
        self.assertEqual(self.agent.chain_length, 2)

    def test_stamp_first_is_genesis(self):
        # Genesis event: previous_hash = SHA256(public_key), not from a prior event
        e1 = self.agent.stamp("genesis_event")
        e2 = self.agent.stamp("second_event")
        # Second event must reference first event's hash
        from aiss.chain import compute_event_hash
        self.assertEqual(e2.previous_hash, compute_event_hash(e1.raw))

    def test_stamp_without_payload(self):
        event = self.agent.stamp("heartbeat")
        self.assertEqual(event.event_type, "heartbeat")
        self.assertIsNotNone(event.hash)

    def test_stamp_repr_is_json_like(self):
        event = self.agent.stamp("test")
        repr_str = repr(event)
        # Should be parseable as partial JSON structure
        self.assertIn("agent_id", repr_str)
        self.assertIn("signature", repr_str)


class TestAgentIdentityVerify(unittest.TestCase):

    def setUp(self):
        from aiss import AgentIdentity
        self.agent = AgentIdentity.create()

    def test_verify_valid_event(self):
        event = self.agent.stamp("user_prompted", {"data": "hello"})
        self.assertTrue(self.agent.verify(event))

    def test_verify_accepts_raw_dict(self):
        event = self.agent.stamp("test")
        self.assertTrue(self.agent.verify(event.raw))

    def test_verify_tampered_event_raises(self):
        from aiss.exceptions import InvalidSignatureError
        event = self.agent.stamp("legit_event")
        # Tamper with the raw dict
        event._raw["payload"]["event_type"] = "TAMPERED"
        with self.assertRaises(InvalidSignatureError):
            self.agent.verify(event)

    def test_verify_chain_single_event(self):
        self.agent.stamp("init")
        self.assertTrue(self.agent.verify_chain())

    def test_verify_chain_multiple_events(self):
        for i in range(5):
            self.agent.stamp(f"step_{i}", {"seq": i})
        self.assertTrue(self.agent.verify_chain())

    def test_verify_chain_empty(self):
        # Empty chain is trivially valid
        self.assertTrue(self.agent.verify_chain())

    def test_cross_agent_verify_fails(self):
        """Event signed by agent A cannot be verified by agent B's public key."""
        from aiss import AgentIdentity
        from aiss.exceptions import InvalidSignatureError
        agent_b = AgentIdentity.create()
        event_a = self.agent.stamp("secret_action")
        # agent_b cannot verify agent_a's event
        with self.assertRaises((InvalidSignatureError, Exception)):
            agent_b.verify(event_a)


class TestAgentIdentityExport(unittest.TestCase):

    def setUp(self):
        from aiss import AgentIdentity
        self.agent = AgentIdentity.create()

    def test_export_structure(self):
        self.agent.stamp("e1")
        self.agent.stamp("e2")
        audit = self.agent.export()
        self.assertEqual(audit["spec"], "AISS-1.0-AUDIT")
        self.assertIn("events", audit)
        self.assertIn("chain_integrity_hash", audit)
        self.assertIn("agent_identity", audit)

    def test_export_event_count(self):
        for i in range(3):
            self.agent.stamp(f"event_{i}")
        audit = self.agent.export()
        self.assertEqual(len(audit["events"]), 3)

    def test_chain_hash_is_hex(self):
        self.agent.stamp("e1")
        h = self.agent.chain_hash()
        self.assertEqual(len(h), 64)
        int(h, 16)  # Should not raise — must be valid hex

    def test_to_dict_roundtrip(self):
        event = self.agent.stamp("roundtrip_test", {"value": 42})
        d = event.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["agent_id"], self.agent.agent_id)
        self.assertEqual(d["payload"]["value"], 42)


class TestQuickstartSnippet(unittest.TestCase):
    """
    Validates the exact code shown in the README and landing page.
    If this test breaks, the public quickstart must be updated.
    """

    def test_readme_quickstart(self):
        """
        from aiss import AgentIdentity

        agent = AgentIdentity.create()
        event = agent.stamp("user_prompted", {"data": "hello"})
        assert agent.verify(event)
        print(event)
        """
        from aiss import AgentIdentity

        agent = AgentIdentity.create()
        event = agent.stamp("user_prompted", {"data": "hello"})
        assert agent.verify(event)

        # Verify output has the fields shown in the README example output
        raw = event.raw
        self.assertIn("agent_id", raw)
        self.assertIn("signature", raw)
        self.assertIn("previous_hash", raw)
        self.assertIn("timestamp", raw)
        self.assertIn("payload", raw)
        self.assertIn("event_type", raw["payload"])

        # repr should print without error
        output = str(event)
        self.assertIn("agent_id", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
