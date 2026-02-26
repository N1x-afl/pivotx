<div align="center">

```
  ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗██╗  ██╗
  ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝╚██╗██╔╝
  ██████╔╝██║██║   ██║██║   ██║   ██║    ╚███╔╝ 
  ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║    ██╔██╗ 
  ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║   ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚═╝  ╚═╝
```

**Framework de Descubrimiento y Pivoting en Redes**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Plataforma](https://img.shields.io/badge/Plataforma-Linux%20%7C%20Kali%20%7C%20Zorin-E95420?style=flat-square&logo=linux&logoColor=white)](https://kali.org)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-00ff9d?style=flat-square)](LICENSE)
[![Versión](https://img.shields.io/badge/Versión-1.0-00d4ff?style=flat-square)]()
[![Mantenido](https://img.shields.io/badge/Mantenido-Sí-green?style=flat-square)]()

*Descubrí hosts, mapeá rutas de pivot, analizá riesgos y generá reportes HTML interactivos — todo en una sola herramienta.*

</div>

---

## ✨ Características

- 🔍 **Descubrimiento de hosts** — ARP sweep (con root) o Ping sweep (sin root), detectado automáticamente
- 🗺️ **Mapa de red interactivo** — nodos arrastrables, coloreados por nivel de riesgo
- 📊 **Gráfico de puertos** — top 10 puertos más comunes visualizados con Chart.js
- ⚡ **Análisis de rutas de pivot** — detecta SSH tunnels, SOCKS5, SMB, WinRM, RDP automáticamente
- 🎯 **Scoring de riesgo** — rankea cada host por potencial de pivoting (CRITICAL / HIGH / MEDIUM / LOW)
- 🖥️ **Banner Grabbing** — captura banners de servicios para fingerprinting
- 📄 **Reporte HTML completo** — interfaz dark cyberpunk, filas expandibles, comandos sugeridos por host
- 📁 **Salida flexible** — guardá reportes en Descargas, Documentos, Escritorio o cualquier ruta
- 🐍 **Python puro** — dependencias mínimas, sin herramientas externas requeridas

---

## 🚀 Inicio Rápido

### Requisitos

```bash
# Python 3.10+
python3 --version

# Instalar dependencias
pip3 install scapy netifaces
```

### Uso básico

```bash
# Escaneo básico (detecta ARP o Ping automáticamente)
sudo python3 pivotx.py -n 192.168.1.0/24

# Guardar reporte en Documentos
sudo python3 pivotx.py -n 192.168.1.0/24 --dir documentos

# Guardar en Descargas con nombre personalizado
sudo python3 pivotx.py -n 192.168.1.0/24 --dir descargas -o mi_reporte.html

# Escaneo agresivo (top 100 puertos, 200 hilos)
sudo python3 pivotx.py -n 192.168.1.0/24 -p top100 -t 200

# Solo descubrir hosts (sin escaneo de puertos)
sudo python3 pivotx.py -n 192.168.1.0/24 --ping-only
```

### ¿Cómo saber cuál es tu red?

```bash
ip route | grep src
# o simplemente:
ip a
```

---

## ⚙️ Opciones

| Flag | Descripción | Default |
|------|-------------|---------|
| `-n`, `--network` | Red objetivo en notación CIDR | *requerido* |
| `-p`, `--ports` | Preset de puertos: `pivot`, `top50`, `top100`, `all` | `pivot` |
| `-o`, `--output` | Nombre del archivo HTML de salida | `pivotx_report.html` |
| `-d`, `--dir` | Alias de carpeta o ruta absoluta | directorio actual |
| `-t`, `--threads` | Hilos para el escaneo de puertos | `100` |
| `--no-banner` | No hacer banner grabbing | desactivado |
| `--ping-only` | Solo descubrimiento, sin escaneo de puertos | desactivado |
| `--top N` | Mostrar solo los top N hosts por score | todos |

### Aliases de carpetas para `--dir`

| Lo que escribís | Carpeta real |
|-----------------|--------------|
| `descargas` / `downloads` | `~/Descargas` o `~/Downloads` |
| `documentos` / `documents` | `~/Documentos` o `~/Documents` |
| `escritorio` / `desktop` | `~/Escritorio` o `~/Desktop` |
| `home` | `~/` |
| `actual` / `cwd` | Directorio actual |

> ✅ Los aliases funcionan tanto en **español como en inglés** — se detectan automáticamente según el idioma del sistema.

---

## 📊 Presets de Puertos

| Preset | Puertos | Ideal para |
|--------|---------|------------|
| `pivot` | 35 puertos clave | Escaneo rápido enfocado en pivoting |
| `top50` | 50 puertos comunes | Reconocimiento general |
| `top100` | 1024 + extras | Escaneo completo |
| `all` | 1–9999 | Cobertura total (lento) |

---

## 🔍 Detección de Pivot

PIVOTX identifica automáticamente oportunidades de pivoting por host:

| Tipo de Host | Detectado por | Métodos sugeridos |
|--------------|---------------|-------------------|
| Linux/SSH | Puerto 22 | `ssh -D` SOCKS5, Chisel, Ligolo-ng |
| Domain Controller | Puertos 88, 389 | Kerberoasting, Pass-the-Hash |
| Windows Host | Puertos 445, 135 | SMB/PsExec, WMIExec, evil-winrm |
| Dispositivo de Red | Puertos 23, 161 | Telnet, SNMP enum |
| Base de Datos | Puertos 3306, 1433, 6379 | UDF injection, xp_cmdshell, RCE |
| Servidor Web | Puertos 80, 443, 8080 | Web shell, reverse shell |

---

## 📄 Contenido del Reporte HTML

- **Header** con red objetivo, fecha, duración, % de red escaneada y host más vulnerable
- **8 métricas** — hosts totales, conteo de riesgo crítico/alto/medio/bajo, exposición SSH/SMB/RDP
- **Mapa de red interactivo** — arrastrá nodos, hover para detalles, coloreado por riesgo
- **Gráfico de barras de puertos** — top 10 puertos encontrados en la red
- **Tabla de hosts** — filas expandibles con banners y comandos copy-paste
- **Cadena de pivot sugerida** — top 5 hosts rankeados por score de pivoting

---

## 🛠️ Cómo Funciona

```
Fase 1 — Descubrimiento    ARP sweep (root) o Ping sweep
Fase 2 — Escaneo           TCP connect multihilo + banner grab
Fase 3 — Análisis          Scoring de riesgo, clasificación de roles, detección de métodos pivot
Fase 4 — Reporte           HTML interactivo con gráficos y mapa de red
```

---

## 📦 Instalación

```bash
git clone https://github.com/TU_USUARIO/pivotx.git
cd pivotx
pip3 install -r requirements.txt
sudo python3 pivotx.py -n 192.168.1.0/24
```

---

## ⚠️ Aviso Legal

> **PIVOTX está diseñado únicamente para pruebas de seguridad autorizadas y fines educativos.**
>
> Usá esta herramienta solo en redes que sean de tu propiedad o para las que tengas permiso explícito por escrito.
> El escaneo de redes sin autorización puede ser ilegal en tu jurisdicción.
> El autor no asume ninguna responsabilidad por el mal uso de esta herramienta.

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Podés:

- 🐛 Reportar bugs en [Issues](../../issues)
- 💡 Sugerir nuevas funciones en [Issues](../../issues)
- 🔧 Enviar pull requests

---

## 📝 Licencia

Este proyecto está bajo la Licencia MIT — consultá el archivo [LICENSE](LICENSE) para más detalles.

---

<div align="center">

Hecho con 🔥 para la comunidad de seguridad informática

⭐ **Si PIVOTX te fue útil, ¡dejá una estrella!** ⭐

</div>
