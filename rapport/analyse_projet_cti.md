# Rapport d'Analyse : Plateforme d'Orchestration Threat Intelligence

Ce document présente une analyse détaillée du projet **Threat Intelligence Analysis Platform**, une solution complète pour la collecte, l'extraction, l'enrichissement et la visualisation de données de cyber-menaces (CTI - Cyber Threat Intelligence).

---

## 1. Vue d'Ensemble du Projet

La plateforme est conçue pour automatiser le cycle de vie du renseignement sur les menaces :
1. **Acquisition** de données brutes depuis de multiples sources.
2. **Extraction** structurée d'indicateurs de compromission (IOC) et de vulnérabilités (CVE).
3. **Normalisation** des données pour assurer une interopérabilité (Format MISP/Standard).
4. **Enrichissement** automatique via Geolocalisation et Analyse NLP.
5. **Visualisation** via un tableau de bord moderne et interactif.

---

## 2. Architecture du Pipeline (Workflow)

Le pipeline est orchestré par le script `run_pipeline.py`. Il suit un processus linéaire et modulaire :

### 📥 Étape 1 : Collecte des Données (`scripts/run_collection_all.py`)
Cette étape interroge diverses sources de flux de menaces (Threat Feeds) pour récupérer les données brutes (JSON, CSV, Texte).
- **Sources incluses** : AbuseIPDB, AlienVault OTX, MalwareBazaar, ThreatFox, URLHaus, etc.
- **Stockage** : Les données brutes sont généralement stockées dans `Sources_data/`.

### 🔍 Étape 2 : Extraction des IOC/CVE (`extraction_ioc_cve/`)
C'est le "moteur" d'intelligence qui parse les données collectées.
- **Extracteurs Spécifiques** : Chaque source possède son propre script (ex: `virustotal_extractor.py`, `nvd_extractor.py`).
- **Types d'indicateurs** : Extraction automatique des adresses IP, domaines, URLs, et identifiants de vulnérabilités (CVE).
- **Format de Sortie** : Les résultats sont sauvegardés dans `output_cve_ioc/`.

### 💎 Étape 3 : Enrichissement (`enrichment/`)
C'est ici que la valeur ajoutée est créée en ajoutant du contexte aux indicateurs bruts (AVANT la normalisation).
- **Géolocalisation** : Utilisation de `GeoManager` pour mapper les IPs à des pays/villes.
- **Analyse NLP** : Résumé automatique des rapports de menaces.
- **Sortie enrichie** : Les fichiers finaux se trouvent dans `output_enrichment/`.

### ⚙️ Étape 4 : Normalisation (`normalisation/`)
Cette étape transforme les données enrichies dans un format standardisé et compatible avec les outils du marché (MISP, etc.).
- **Conversion MISP** : Utilisation de `misp_converter.py` et `misp_normalizer.py`.
- **Standardisation** : Nettoyage des doublons et uniformisation des champs.
- **Sortie normalisée** : Les résultats sont stockés dans `output_normaliser/`.

---

## 3. Interface et Visualisation

Le projet inclut une application web complète pour piloter le pipeline et analyser les données.

### 🖥️ Frontend (React + Vite)
- **Localisation** : `/frontend`
- **Technologie** : React.js avec une esthétique moderne (style "SOC/Cyberpunk").
- **Fonctionnalités** : Visualisation en temps réel de la santé des sources, graphiques de distribution géographique, tableaux de données filtrables.

### ⚙️ Backend (FastAPI)
- **Localisation** : `/backend`
- **Rôle** : Fournit une API REST pour alimenter le frontend, gérer les exécutions du pipeline et interroger la base de données.

---

## 4. Composants Additionnels

- **MISP Integration** (`misp_integration/`) : Permet l'exportation automatique des événements enrichis vers une instance MISP locale (via Docker).
- **Base de Données** (`database/`) : Utilisation de SQLite pour le stockage persistant des indicateurs et de l'historique des exécutions.
- **Suivi des "Runs"** (`runs.json`) : Un fichier de tracking qui enregistre chaque exécution du pipeline avec les statistiques de réussite/échec.

---

## 5. Fichiers Clés à Connaître

| Fichier / Dossier | Rôle |
| :--- | :--- |
| `run_pipeline.py` | Le chef d'orchestre principal (Step-by-Step execution). |
| `run_platform.py` | Démarre simultanément le backend et le frontend. |
| `.env` | Contient les clés API et les configurations sensibles. |
| `extraction_ioc_cve/base_extractor.py` | La classe parente dont héritent tous les extracteurs. |
| `enrichment/geolocalisation/geo_manager.py` | Gestionnaire haute performance de la géolocalisation. |

---

## Conclusion
Le projet est extrêmement bien structuré et suit les meilleures pratiques de l'ingénierie CTI. Sa modularité permet d'ajouter facilement de nouvelles sources ou de nouvelles méthodes d'enrichissement sans casser le flux existant.
