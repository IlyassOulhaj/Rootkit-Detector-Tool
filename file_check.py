import hashlib
import os
import json
from typing import Dict, List, Optional

TARGET_FILES: List[str] = [
    '/bin/ls',
    '/bin/cat',
    '/bin/ps',
    '/bin/netstat',
    '/bin/login',
    '/usr/bin/top',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
]
CHUNK_SIZE: int = 65536
SIGNATURES_FILE: str = "signatures.json"


def calculate_sha256(filepath: str) -> str:
    """Calcule le hash SHA-256 d'un fichier."""
    if not os.path.exists(filepath):
        return "MISSING"

    hasher = hashlib.sha256()

    try:
        with open(filepath, 'rb') as file:
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    except IOError as e:
        return f"IO_ERROR:{e.__class__.__name__}"


def generate_reference_database():
    """Génère le fichier signatures.json. À exécuter UNE FOIS sur un système propre."""
    print(f" Génération de la base de référence dans {SIGNATURES_FILE}...")
    signatures: Dict[str, str] = {}

    for filepath in TARGET_FILES:
        current_hash = calculate_sha256(filepath)

        if current_hash not in ["MISSING", "IO_ERROR:PermissionError", "IO_ERROR:IOError"]:
            signatures[filepath] = current_hash
            print(f"-> {filepath}: {current_hash[:16]}...")
        elif current_hash == "IO_ERROR:PermissionError":
            print(f"Avertissement : Impossible de lire {filepath} (Permission refusée). Skip.")
        else:
            print(f"Erreur : {filepath} introuvable ou autre erreur. Skip.")

    try:
        with open(SIGNATURES_FILE, 'w') as f:
            json.dump(signatures, f, indent=4)
        print(f"\n Base de référence enregistrée avec {len(signatures)} signatures.")

    except Exception as e:
        print(f"Erreur critique lors de l'écriture du fichier de signatures : {e}")


def load_signatures() -> Optional[Dict[str, str]]:
    """Charge la base de référence JSON."""
    try:
        with open(SIGNATURES_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERREUR : Le fichier de signatures **{SIGNATURES_FILE}** est introuvable. Impossible de scanner.")
        return None
    except json.JSONDecodeError:
        print(f"ERREUR : Le fichier de signatures est mal formé.")
        return None


def scan_files() -> bool:
    """Compare les hashs actuels avec la base de référence."""
    print("🛡️ Démarrage du File Scanner (Vérification d'Intégrité)...")
    reference_hashes = load_signatures()

    if reference_hashes is None:
        return True

    anomalies_detected: bool = False

    for filepath, expected_hash in reference_hashes.items():
        current_hash = calculate_sha256(filepath)

        if current_hash.startswith("IO_ERROR"):
            print(f"ATTENTION : Impossible de lire **{filepath}** ({current_hash}).")
            anomalies_detected = True
        elif current_hash == "MISSING":
            print(f"ALERTE ROUGE : Fichier critique **{filepath}** MANQUANT!")
            anomalies_detected = True
        elif current_hash != expected_hash:
            print(f"ALERTE ROUGE : **{filepath}** MODIFIÉ (Trojanisé)!")
            anomalies_detected = True
        else:
            print(f" OK : {filepath} intègre.")

    if anomalies_detected:
        print("\n**Bilan** : Anomalies d'intégrité détectées.")
        return True
    else:
        print("\n**Bilan** : Tous les fichiers critiques sont intègres.")
        return False

if __name__ == '__main__':
    
    generate_reference_database()
    scan_files()