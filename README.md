# Secrets Sentinel

> Detecta posibles credenciales antes de subir código a Git.

**Secrets Sentinel** es una CLI local y sin dependencias que busca patrones de alto riesgo en archivos de texto: claves AWS, tokens de GitHub, claves privadas, URLs con credenciales y asignaciones sospechosas de API keys. Nunca envía el contenido a ningún servicio.

## Features

- Escaneo recursivo de carpetas.
- Reglas explicables con nivel de severidad.
- Omite carpetas habituales como `.git`, `node_modules` y `.venv`.
- Salida de consola y reporte JSON.
- Modo `--strict` con código de salida no cero, útil para CI.

## Uso

```bash
python sentinel.py . --report findings.json
python sentinel.py ./src --strict
```

## Demo

```text
HIGH   config.py:8  GitHub token-like value
MEDIUM .env:2       Generic API key assignment
Summary: 2 findings
```

## Stack

Python 3.10+ y librería estándar. No requiere instalación.

## English

Secrets Sentinel is a privacy-first, dependency-free CLI that scans local text files for likely credentials before they reach Git. It reports explainable findings, supports JSON output and can fail a CI job in strict mode.

## License

MIT © 2026 Álvaro Alcalá
