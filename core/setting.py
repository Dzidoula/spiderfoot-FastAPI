import os
import importlib

# Lire la variable d'environnement ENV
env = os.getenv("ENV", "local")  # Valeur par défaut : "local"

# Importer dynamiquement le bon module
try:
    config = importlib.import_module(f"config.{env}")
except ModuleNotFoundError:
    raise ValueError(f"Configuration inconnue : {env}")

# Utilisation des constantes
print(f"env = {env}")


