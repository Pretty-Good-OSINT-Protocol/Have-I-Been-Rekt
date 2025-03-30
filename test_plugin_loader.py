import unittest
from src import plugin_loader

class TestPluginLoader(unittest.TestCase):
    def test_load_plugins(self):
        plugins = plugin_loader.load_plugins()
        self.assertIsInstance(plugins, list)

if __name__ == "__main__":
    unittest.main()
