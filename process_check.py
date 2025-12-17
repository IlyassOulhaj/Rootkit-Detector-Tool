import os
import subprocess
import sys
import time

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
    
    print("[*] Lecture de la liste 'ps'...")
    visible = get_visible_pids()
    
    print("[*] Scan Brute-force en cours...")
    real = get_hidden_pids_bruteforce()

    suspects = real - visible
    
    if not suspects:
        print("\n[OK] Aucun processus caché détecté.")
        return False

    print(f"    -> {len(suspects)} candidats suspects trouvés. Vérification...")

    time.sleep(1) 
    visible_update = get_visible_pids()
    
    confirmed_hidden = suspects - visible_update

    if confirmed_hidden:
        print(f"\n[!] ALERTE : {len(confirmed_hidden)} VRAIS processus cachés détectés !")
        
        for pid in confirmed_hidden:
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    name = f.read().strip()
                print(f"    - PID {pid}: {name} (CACHÉ)")
            except:
                print(f"    - PID {pid}: ???")
        return True
    else:
        print("\n[OK] Fausse alerte (c'était juste des processus démarrés pendant le scan).")
        return False

# Bloc pour tester ton module tout seul sans attendre les autres
if __name__ == "__main__":
    scan_process()
