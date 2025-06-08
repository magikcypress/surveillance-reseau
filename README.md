# Surveillance Réseau

Application de surveillance réseau permettant de monitorer l'état des équipements réseau et de visualiser les métriques en temps réel.

## Fonctionnalités

- Surveillance des équipements réseau (ping, disponibilité)
- Analyse des ports ouverts
- Visualisation des métriques en temps réel
- Interface web intuitive
- Alertes en cas de problème

## Installation

1. Cloner le repository

```bash
git clone [URL_DU_REPO]
cd surveillance-reseau
```

2. Installer les dépendances

```bash
npm install
```

3. Lancer l'application

```bash
npm run dev
```

## Configuration

L'application nécessite des droits administrateur pour certaines fonctionnalités (scan nmap, etc.).

## Technologies utilisées

- Node.js
- Express
- Socket.IO
- Chart.js
- Nmap
