#!/bin/bash
# Script de démarrage pour l'application Test de Débit Réseau

# ============================================================================
# CONFIGURATION RADIUS
# ============================================================================

export RADIUS_SERVER="home.local"
export RADIUS_SECRET="******"
export RADIUS_PORT="1812"
export RADIUS_TIMEOUT="5"
export RADIUS_RETRIES="2"

export RADIUS_NAS_IDENTIFIER="NFM"
export RADIUS_NAS_IP="192.x.x.60"

export RADIUS_ALLOWED_GROUPS="GRP-RAD-NFM"
export RADIUS_GROUP_ATTRIBUTE="Class"

# ============================================================================
# DÉMARRAGE
# ============================================================================

echo "🔧 Configuration RADIUS :"
echo "   Serveur: $RADIUS_SERVER:$RADIUS_PORT"
echo "   NAS: $RADIUS_NAS_IDENTIFIER ($RADIUS_NAS_IP)"

# Démarrer l'application
python3 app.py
