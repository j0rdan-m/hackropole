# sqli-detector

# 🐍 SQLi Final Tester – Blind Injection Multi-SGBD

Script Python complet pour tester et exploiter une injection SQL de type blind sur des APIs REST JSON.  
Supporte la détection automatique du SGBD, l'extraction du schéma, et la récupération ciblée de données (ex: flags).

---

## ✅ Fonctionnalités

- Test d'injection SQL basique (`' OR 1=1`)
- Détection du **SGBD et version** (`MySQL`, `PostgreSQL`, `SQLite`)
- Extraction du **schéma de la base** (tables + colonnes)
- Extraction de **colonnes ciblées** par mot-clé (`flag`, `password`, etc.)

---

## 📦 Installation

```bash
pip install requests
```

---

## 🚀 Utilisation

```bash
python3 sqli_tester_final.py <URL> [options]
```

### 🔧 Options disponibles

| Option                     | Description |
|----------------------------|-------------|
| `<URL>`                   | Endpoint vulnérable (POST JSON) |
| `--delay`                 | Délai entre requêtes (default: 1s) |
| `--extract-sgbd`          | Détecte le nom et la version du SGBD |
| `--extract-schema`        | Extrait les noms de tables et colonnes |
| `--wanted-key <mot>`      | Cherche des colonnes contenant ce mot et en extrait le contenu |

---

## 🧪 Exemples

### 1. 🔍 Test de vulnérabilité SQLi uniquement

```bash
python3 sqli_tester_final.py http://target/api/login
```

### 2. 🧠 Détection du SGBD

```bash
python3 sqli_tester_final.py http://target/api/login --extract-sgbd
```

### 3. 🧱 Dump complet du schéma

```bash
python3 sqli_tester_final.py http://target/api/login --extract-schema --extract-sgbd
```

### 4. 🗝 Extraction d’un flag ou d’un secret

```bash
python3 sqli_tester_final.py http://target/api/login --extract-sgbd --extract-schema --wanted-key flag
```

---

## ⚠️ Avertissement

> Ce script est à usage **strictement pédagogique**.  
> Utilisation uniquement autorisée en CTFs ou environnements de test contrôlés.

---

🎯 Happy Hacking!
