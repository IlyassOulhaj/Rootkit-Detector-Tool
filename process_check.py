import os
import subprocess
import sys

def get_visible_pids():
    """
    Vue 1 : La liste 'officielle' donnée par la commande ps.
    C'est celle que le Rootkit va essayer de modifier.
    """
    visible_pids = set()
    try:
        # On exécute la commande 'ps -e' qui liste tous les processus
        # check_output renvoie le résultat sous forme de bytes, on le décode en string
        output = subprocess.check_output(['ps', '-e']).decode('utf-8')
        
        # On lit ligne par ligne
        for line in output.splitlines()[1:]:  # On saute la 1ère ligne (les titres)
            parts = line.split()
            if parts:
                pid = int(parts[0]) # Le PID est le premier nombre de la ligne
                visible_pids.add(pid)
    except Exception as e:
        print(f"[ERREUR] Impossible de lancer ps : {e}")
    
    return visible_pids

def get_hidden_pids_bruteforce():
    """
    Vue 2 : La méthode 'Brute Force'.
    On teste tous les numéros de 1 à l'infini (max_pid) pour voir s'ils répondent.
    """
    real_pids = set()
    
    # Trouver le PID maximum sur ce système (souvent 32768)
    try:
        with open('/proc/sys/kernel/pid_max', 'r') as f:
            max_pid = int(f.read())
    except:
        max_pid = 32768 # Valeur par défaut si on ne trouve pas le fichier
    
    print(f"[*] Scan de 1 à {max_pid} PIDs en cours... (patience)")

    for pid in range(1, max_pid + 1):
        try:
            # os.kill(pid, 0) n'envoie PAS de signal de mort.
            # C'est une astuce : ça vérifie juste si le processus peut recevoir un signal.
            os.kill(pid, 0)
            
            # Si aucune erreur n'est levée, le processus EXISTE.
            real_pids.add(pid)
            
        except ProcessLookupError:
            # Le processus n'existe pas, on passe au suivant.
            pass
        except PermissionError:
            # Le processus existe (ex: appartient à Root), mais on n'a pas les droits.
            # S'il existe, on l'ajoute quand même !
            real_pids.add(pid)
        except OSError:
            pass

    return real_pids

def scan_process():
    print("--- Démarrage du Module Processus (Ilyass) ---")
    
    # 1. Récupérer la vue "normale"
    print("[*] Lecture de la liste 'ps'...")
    visible = get_visible_pids()
    print(f"    -> {len(visible)} processus visibles trouvés.")

    # 2. Récupérer la vue "brute force"
    # Note : Ça peut prendre quelques secondes
    real = get_hidden_pids_bruteforce()
    print(f"    -> {len(real)} processus réels trouvés par brute-force.")

    # 3. Comparer (PIDs cachés = Réels - Visibles)
    hidden = real - visible
    
    if hidden:
        print(f"\n[!] ALERTE : {len(hidden)} processus cachés détectés !")
        print(f"[!] PIDs suspects : {hidden}")
        
        # Petit bonus : Essayer de lire le nom des processus cachés
        for pid in hidden:
            try:
                # On essaie de lire le nom dans /proc/PID/comm
                with open(f'/proc/{pid}/comm', 'r') as f:
                    name = f.read().strip()
                print(f"    - PID {pid}: {name}")
            except:
                print(f"    - PID {pid}: (Nom inaccessible)")
        return True # Retourne True car on a trouvé une infection
    else:
        print("\n[OK] Aucun processus caché détecté.")
        return False

# Bloc pour tester ton module tout seul sans attendre les autres
if __name__ == "__main__":
    scan_process()
