#!/usr/bin/env python3
import sys
import os
import site

print("=" * 60)
print("DIAGNOSTIC PYTHON")
print("=" * 60)
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"Python path: {sys.path}")

print("\n" + "=" * 60)
print("RECHERCHE DES MODULES")
print("=" * 60)

# Vérifier OpenSSL
try:
    import OpenSSL
    print(f"✓ OpenSSL trouvé: {OpenSSL.__file__}")
    print(f"  Version: {OpenSSL.__version__ if hasattr(OpenSSL, '__version__') else 'inconnue'}")
except ImportError as e:
    print(f"✗ OpenSSL non trouvé: {e}")

# Vérifier cryptography
try:
    import cryptography
    print(f"✓ cryptography trouvé: {cryptography.__file__}")
    print(f"  Version: {cryptography.__version__ if hasattr(cryptography, '__version__') else 'inconnue'}")
except ImportError as e:
    print(f"✗ cryptography non trouvé: {e}")

# Vérifier les autres dépendances
deps = [
    ('flask', 'Flask'),
    ('nmap', 'python-nmap'),
    ('apscheduler', 'APScheduler'),
    ('reportlab', 'reportlab')
]

print("\n" + "=" * 60)
print("AUTRES DÉPENDANCES")
print("=" * 60)

for module_name, package_name in deps:
    try:
        module = __import__(module_name)
        print(f"✓ {module_name} trouvé")
    except ImportError:
        print(f"✗ {module_name} non trouvé (package: {package_name})")

print("\n" + "=" * 60)
print("RÉPERTOIRES D'INSTALLATION")
print("=" * 60)

# Lister les répertoires où pip installe les packages
try:
    import subprocess
    result = subprocess.run(['pip3', 'list', '--format=freeze'], capture_output=True, text=True)
    print("Paquets installés avec pip3:")
    for line in result.stdout.split('\n')[:10]:  # Afficher seulement les 10 premiers
        print(f"  {line}")
except:
    pass

print("\n" + "=" * 60)
print("SITES-PACKAGES")
print("=" * 60)
for path in site.getsitepackages():
    print(f"  {path}")
    # Vérifier si les modules sont dans ce répertoire
    openssl_path = os.path.join(path, 'OpenSSL')
    crypto_path = os.path.join(path, 'cryptography')
    if os.path.exists(openssl_path):
        print(f"    → OpenSSL trouvé ici")
    if os.path.exists(crypto_path):
        print(f"    → cryptography trouvé ici")