"""Checks that the Python bindings reproduce the kernel's golden vectors (WIRE §8).

Run with `tools/test-python-vectors.sh` (builds the module and runs this file), or against a built module, for example:

    maturin develop -m crates/bindings/python/Cargo.toml
    python -m unittest discover -s crates/bindings/python/tests

or, without installing, with the cdylib copied next to this file as fieldseal.abi3.so.
"""

import json
import pathlib
import unittest

import fieldseal

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "kernel" / "tests" / "vectors"


def load(name):
    return json.loads((VECTORS / name).read_text())


class CanonicalCbor(unittest.TestCase):
    def test_wire_006_json_vectors(self):
        for case in load("cbor.json")["from_json"]:
            with self.subTest(case["id"]):
                self.assertEqual(fieldseal.canonical_cbor_from_json(case["json"]).hex(), case["cbor"])

    def test_wire_001_key_order_is_independent_of_input_order(self):
        a = fieldseal.canonical_cbor_from_json('{"aa": 1, "b": 2, "a": 3}')
        b = fieldseal.canonical_cbor_from_json('{"a": 3, "b": 2, "aa": 1}')
        self.assertEqual(a, b)
        self.assertEqual(a.hex(), "a361610361620262616101")

    def test_wire_003_rejects_duplicate_keys(self):
        with self.assertRaises(fieldseal.WireError) as cm:
            fieldseal.canonical_cbor_from_json('{"a": 1, "a": 2}')
        self.assertEqual(cm.exception.args[0], "E_CBOR_DUPLICATE")

    def test_wire_004_rejects_non_nfc_text(self):
        with self.assertRaises(fieldseal.WireError) as cm:
            fieldseal.canonical_cbor_from_json('"e\\u0301"')
        self.assertEqual(cm.exception.args[0], "E_CBOR_NONCANONICAL")

    def test_wire_006_rejects_values_outside_the_model(self):
        for text in ["null", "NaN", "Infinity", "[1, null]", "18446744073709551616"]:
            with self.subTest(text), self.assertRaises(fieldseal.WireError):
                fieldseal.canonical_cbor_from_json(text)


class Identifiers(unittest.TestCase):
    def test_wire_011_content_addresses(self):
        for case in load("identifiers.json")["content_addresses"]:
            with self.subTest(case["id"]):
                self.assertEqual(fieldseal.content_address(bytes.fromhex(case["bytes"])), case["address"])

    def test_wire_010_key_ids(self):
        for case in load("identifiers.json")["key_ids"]:
            with self.subTest(case["id"]):
                self.assertEqual(fieldseal.key_id(bytes.fromhex(case["public_key"])).hex(), case["key_id"])

    def test_wire_185_fingerprints(self):
        for case in load("identifiers.json")["fingerprints"]:
            with self.subTest(case["id"]):
                fp = fieldseal.fingerprint(bytes.fromhex(case["salt"]), bytes.fromhex(case["canonical"]))
                self.assertEqual(fp.hex(), case["fingerprint"])


if __name__ == "__main__":
    unittest.main()
