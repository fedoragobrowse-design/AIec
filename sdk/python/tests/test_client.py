import base64
import json
import unittest

from aiec.client import AIec, Sandbox


class ClientContractTest(unittest.TestCase):
    def test_context_manager_and_file_operations_use_api_contract(self):
        client = AIec(api_key="af_live_" + "0" * 48, base_url="http://example")
        sandbox = Sandbox(client, {"id": "sandbox-1"})
        calls = []

        def request(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "DELETE":
                return None
            if method == "GET" and path.endswith("/files/content?path=%2Fworkspace%2Fproof.txt"):
                return {"content_base64": base64.b64encode(b"proof").decode()}
            return {"ok": True}

        client._request = request
        with sandbox as box:
            box.write_file("/workspace/proof.txt", b"proof")
            self.assertEqual(box.read_file("/workspace/proof.txt"), b"proof")
            box.make_directory("/workspace/subdir")
            box.list_files()
            box.delete_file("/workspace/proof.txt")
        self.assertEqual(calls[0][:2], ("PUT", "/v1/sandboxes/sandbox-1/files"))
        self.assertEqual(calls[-2][:2], ("DELETE", "/v1/sandboxes/sandbox-1/files?path=%2Fworkspace%2Fproof.txt"))
        self.assertEqual(calls[-1][:2], ("DELETE", "/v1/sandboxes/sandbox-1"))
        self.assertEqual(json.loads(json.dumps(calls[0][2]))["path"], "/workspace/proof.txt")


if __name__ == "__main__":
    unittest.main()
