import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.api_analysis import analyze_asyncapi, analyze_graphql_schema
from sentinel.artifact_analysis import inspect_artifact
from sentinel.cloud_analysis import analyze_cloud_json
from sentinel.db import connect, now


class CloudArtifactApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            eid = conn.execute("INSERT INTO engagements(name,created_at) VALUES('demo',?)", (now(),)).lastrowid
            conn.execute("INSERT INTO scope(engagement_id,kind,value,allow_subdomains) VALUES(?,'domain','example.com',1)", (eid,))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_terraform_public_sensitive_port(self):
        plan = {"resource_changes": [{"address": "aws_security_group.bad", "type": "aws_security_group", "change": {"after": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}]}}}]}
        path = Path(self.temp.name) / "plan.json"
        path.write_text(json.dumps(plan))
        result = analyze_cloud_json("demo", "terraform", path)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_terraform_multi_cloud_public_access(self):
        plan = {"resource_changes": [
            {"address": "google_storage_bucket_iam_member.public", "type": "google_storage_bucket_iam_member", "change": {"after": {"member": "allUsers", "role": "roles/storage.objectViewer"}}},
            {"address": "azurerm_network_security_rule.rdp", "type": "azurerm_network_security_rule", "change": {"after": {"access": "Allow", "source_address_prefix": "*", "destination_port_range": "3389"}}},
        ]}
        path = Path(self.temp.name) / "multi-cloud.json"
        path.write_text(json.dumps(plan))
        titles = {item["title"] for item in analyze_cloud_json("demo", "terraform", path)["findings"]}
        self.assertIn("Cloud storage IAM binding grants public access", titles)
        self.assertIn("Sensitive service is exposed by an Azure network security rule", titles)

    def test_kubernetes_privileged_container(self):
        manifest = {"kind": "Deployment", "metadata": {"name": "bad"}, "spec": {"template": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}}}
        path = Path(self.temp.name) / "k8s.json"
        path.write_text(json.dumps(manifest))
        result = analyze_cloud_json("demo", "kubernetes", path)
        self.assertTrue(any(item["severity"] == "critical" for item in result["findings"]))

    def test_artifact_inspection_never_extracts_or_executes(self):
        artifact = Path(self.temp.name) / "firmware.bin"
        artifact.write_bytes(b"HEADER" + b"hsqs" + b"\x00" * 100 + b"\x7fELF")
        result = inspect_artifact("demo", artifact)
        self.assertFalse(result["extraction_performed"])
        self.assertFalse(result["execution_performed"])
        self.assertEqual({item["type"] for item in result["embedded_signatures"]}, {"SquashFS filesystem", "ELF executable"})

    def test_asyncapi_is_scoped_and_offline(self):
        spec = {"asyncapi": "2.6.0", "servers": {"prod": {"url": "api.example.com:1883", "protocol": "mqtt"}}, "channels": {"events": {"publish": {"security": []}}}}
        path = Path(self.temp.name) / "async.json"
        path.write_text(json.dumps(spec))
        result = analyze_asyncapi("demo", path)
        self.assertEqual(result["operations"], 1)
        self.assertGreaterEqual(result["observations"], 2)

    def test_graphql_introspection_is_not_executed(self):
        schema = {"data": {"__schema": {"mutationType": {"name": "Mutation"}, "types": [{"name": "Mutation", "fields": [{"name": "deleteUser"}, {"name": "updateProfile"}]}]}}}
        path = Path(self.temp.name) / "graphql.json"
        path.write_text(json.dumps(schema))
        result = analyze_graphql_schema("demo", path)
        self.assertEqual(result["mutations"], 2)
        self.assertFalse(result["introspection_execution"])
        self.assertIn("deleteUser", result["sensitive_mutation_names"])


if __name__ == "__main__":
    unittest.main()
