import unittest
from src.osint_core import lookup_domain

class TestOSINTCore(unittest.TestCase):
    def test_lookup_domain(self):
        result = lookup_domain("example.com")
        self.assertEqual(result["domain"], "example.com")

if __name__ == '__main__':
    unittest.main()
