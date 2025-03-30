import importlib
import os

PLUGIN_DIR = "plugins"

def load_plugins():
    plugins = []
    for filename in os.listdir(PLUGIN_DIR):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = f"{PLUGIN_DIR}.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                plugins.append(module)
            except Exception as e:
                print(f"Failed to load {module_name}: {e}")
    return plugins

if __name__ == "__main__":
    loaded = load_plugins()
    print(f"Loaded {len(loaded)} plugins.")
