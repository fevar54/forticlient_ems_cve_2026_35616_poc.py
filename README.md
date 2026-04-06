markdown
# CVE-2026-35616 - FortiClient EMS API Authentication Bypass Detector

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-detection-orange.svg)]()

<div align="center">
  <h3>⚠️ CRITICAL SECURITY VULNERABILITY ⚠️</h3>
  <p><strong>CVSS Score: 9.1 | CWE-284: Improper Access Control</strong></p>
  <p>FortiClient EMS versions 7.4.5 through 7.4.6</p>
</div>

---

## 📋 Descripción

Este detector identifica si un servidor **FortiClient EMS** es vulnerable a **CVE-2026-35616**, una vulnerabilidad crítica de bypass de autenticación en la API.

Un atacante **no autenticado** puede acceder a endpoints sensibles de la API y potencialmente ejecutar código o comandos en el servidor.

> **⚠️ ADVERTENCIA:** Esta herramienta es SOLO para pruebas de seguridad autorizadas en entornos controlados. No la uses contra sistemas que no te pertenezcan.

---

## 🔍 ¿Cómo funciona?

El detector realiza peticiones GET **sin autenticación** a endpoints conocidos de la API de FortiClient EMS:

- Si un endpoint devuelve `200 OK` → El sistema es **VULNERABLE**
- Si devuelve `401 Unauthorized` o `403 Forbidden` → El endpoint está **protegido**
┌─────────────────┐ GET /api/v1/system/status ┌─────────────────┐
│ Detector │ ─────────────────────────────────► │ FortiClient │
│ │ (sin autenticación) │ EMS │
│ │ ◄───────────────────────────────── │ │
└─────────────────┘ 200 OK → ¡VULNERABLE! └─────────────────┘

text

---

## 📦 Requisitos

- Python 3.6 o superior
- Biblioteca `requests`

---

## 🚀 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/TU-USUARIO/CVE-2026-35616-Detector
cd CVE-2026-35616-Detector

# Instalar dependencias
pip install -r requirements.txt
