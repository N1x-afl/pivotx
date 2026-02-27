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
[![Plataforma](https://img.shields.io/badge/Plataforma-Linux%20%7C%20Kali%20%7C%20Zsh-E95420?style=flat-square&logo=linux&logoColor=white)](https://kali.org)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-00ff9d?style=flat-square)](./LICENSE)
[![Versión](https://img.shields.io/badge/Versión-1.0-00d4ff?style=flat-square)](.)
[![Mantenido](https://img.shields.io/badge/Mantenido-Sí-green?style=flat-square)](.)
[![Uso Ético](https://img.shields.io/badge/Uso-Solo%20Autorizado-red?style=flat-square)](.)

*Descubrí hosts, mapeá rutas de pivot, analizá riesgos y generá reportes HTML interactivos — todo en una sola herramienta.*

</div>

---

## 📑 Tabla de Contenidos

- [¿Qué es PIVOTX?](#-qué-es-pivotx)
- [Características](#-características)
- [Requisitos del Sistema](#-requisitos-del-sistema)
- [Instalación](#-instalación)
- [Inicio Rápido](#-inicio-rápido)
- [Uso Detallado](#-uso-detallado)
- [Presets de Puertos](#-presets-de-puertos)
- [Detección de Pivot](#-detección-de-pivot)
- [Reporte HTML](#-reporte-html)
- [Casos de Uso](#-casos-de-uso)
- [Troubleshooting](#-troubleshooting)
- [Contribuciones](#-contribuciones)
- [Aviso Legal](#-aviso-legal)
- [Licencia](#-licencia)

---

## 🔎 ¿Qué es PIVOTX?

PIVOTX es un framework de reconocimiento y análisis de pivoting en redes, pensado para **profesionales de seguridad ofensiva y defensiva** que necesiten mapear rápidamente una red, identificar hosts vulnerables y generar un reporte accionable con comandos listos para usar en una sesión de pentest autorizada.

A diferencia de herramientas como Nmap (que requieren post-procesamiento manual) o scripts sueltos, PIVOTX integra en un único flujo:

1. **Descubrimiento de hosts** (ARP o ICMP según privilegios)
2. **Escaneo de puertos** multihilo con banner grabbing
3. **Análisis de riesgo** y scoring de potencial de pivoting
4. **Generación de reporte HTML** interactivo con mapa de red, gráficos y comandos copy-paste

Es ideal para fases de **post-explotación** y **movimiento lateral** en compromisos de red interna.

---

## ✨ Características

| Característica | Descripción |
|---|---|
| 🔍 **Descubrimiento automático** | ARP sweep con root (preciso) o Ping sweep sin root (compatible) |
| 🗺️ **Mapa de red interactivo** | Nodos arrastrables, coloreados por nivel de riesgo |
| 📊 **Gráfico de puertos** | Top 10 puertos más comunes visualizados con Chart.js |
| ⚡ **Detección de rutas de pivot** | SSH tunnels, SOCKS5, SMB, WinRM, RDP, Kerberos, SNMP y más |
| 🎯 **Scoring de riesgo** | Rankea cada host: CRITICAL / HIGH / MEDIUM / LOW |
| 🖥️ **Banner Grabbing** | Fingerprinting de servicios por captura de banners |
| 📄 **Reporte HTML completo** | Interfaz dark cyberpunk, filas expandibles, comandos por host |
| 📁 **Salida flexible** | Guardá reportes en Descargas, Documentos, Escritorio o ruta absoluta |
| 🧵 **Escaneo multihilo** | Hasta 200+ hilos configurables para velocidad máxima |
| 🐍 **Python puro** | Dependencias mínimas, sin herramientas externas requeridas |
| 🌐 **Aliases bilingües** | Carpetas en español e inglés detectadas automáticamente |

---

## 🖥️ Requisitos del Sistema

### Sistema operativo

PIVOTX está optimizado para entornos Linux orientados a seguridad:

- **Kali Linux** (recomendado)
- **Parrot OS**
- **Ubuntu 20.04+** / **Debian 11+**
- **Cualquier distribución Linux con Python 3.10+**

> ⚠️ **Windows y macOS no son soportados oficialmente.** Scapy requiere configuración adicional en esos entornos y el ARP sweep puede no funcionar correctamente.

### Dependencias de Python

| Paquete | Versión mínima | Uso |
|---|---|---|
| `Python` | 3.10+ | Intérprete base |
| `scapy` | 2.5.0+ | ARP sweep (requiere root) |
| `netifaces` | 0.11.0+ | Detección de interfaces de red |

### Privilegios

| Modo | Requiere root | Método de descubrimiento |
|---|---|---|
| **Completo** | ✅ Sí (`sudo`) | ARP sweep — más rápido y confiable |
| **Sin privilegios** | ❌ No | Ping sweep — puede omitir hosts con ICMP bloqueado |

---

## 📦 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/N1x-afl/pivotx.git
cd pivotx
```

### 2. Instalar dependencias

```bash
pip3 install -r requirements.txt
```

O manualmente:

```bash
pip3 install scapy netifaces
```

### 3. Verificar instalación

```bash
python3 pivotx.py --help
```

Deberías ver el banner ASCII y el menú de ayuda.

### 4. (Opcional) Instalar como comando global

```bash
sudo cp pivotx.py /usr/local/bin/pivotx
sudo chmod +x /usr/local/bin/pivotx
# Ahora podés usar: sudo pivotx -n 192.168.1.0/24
```

---

## 🚀 Inicio Rápido

### ¿Cuál es tu red?

Si no sabés tu rango de red, usá:

```bash
ip route | grep src
# o
ip a
# Buscá la línea con inet, por ejemplo: inet 192.168.1.100/24
```

### Escaneo básico

```bash
# Escaneo estándar — detecta ARP o Ping automáticamente
sudo python3 pivotx.py -n 192.168.1.0/24
```

### Guardar reporte

```bash
# En la carpeta Documentos
sudo python3 pivotx.py -n 192.168.1.0/24 --dir documentos

# En Descargas con nombre personalizado
sudo python3 pivotx.py -n 192.168.1.0/24 --dir descargas -o reporte_cliente.html

# En ruta absoluta
sudo python3 pivotx.py -n 192.168.1.0/24 --dir /opt/pentests/cliente_xyz/
```

---

## 🔧 Uso Detallado

### Sintaxis

```
sudo python3 pivotx.py -n <RED/CIDR> [opciones]
```

### Referencia de flags

| Flag | Descripción | Default |
|---|---|---|
| `-n`, `--network` | Red objetivo en notación CIDR (ej: `10.10.10.0/24`) | *requerido* |
| `-p`, `--ports` | Preset de puertos: `pivot`, `top50`, `top100`, `all` | `pivot` |
| `-o`, `--output` | Nombre del archivo HTML de salida | `pivotx_report.html` |
| `-d`, `--dir` | Alias de carpeta o ruta absoluta de destino | directorio actual |
| `-t`, `--threads` | Número de hilos para el escaneo de puertos | `100` |
| `--no-banner` | Desactivar banner grabbing (más rápido, menos info) | desactivado |
| `--ping-only` | Solo descubrimiento de hosts, sin escaneo de puertos | desactivado |
| `--top N` | Mostrar solo los top N hosts ordenados por score | todos |

### Aliases de carpetas para `--dir`

| Alias | Carpeta real |
|---|---|
| `descargas` / `downloads` | `~/Descargas` o `~/Downloads` |
| `documentos` / `documents` | `~/Documentos` o `~/Documents` |
| `escritorio` / `desktop` | `~/Escritorio` o `~/Desktop` |
| `home` | `~/` |
| `actual` / `cwd` | Directorio actual |

> Los aliases funcionan tanto en **español como en inglés** — detectados automáticamente según el idioma del sistema operativo.

### Ejemplos de uso

```bash
# Descubrir hosts rápido sin escanear puertos
sudo python3 pivotx.py -n 192.168.0.0/24 --ping-only

# Escaneo agresivo: top 100 puertos, 200 hilos
sudo python3 pivotx.py -n 10.10.10.0/24 -p top100 -t 200

# Escaneo completo (lento, cobertura total de puertos)
sudo python3 pivotx.py -n 172.16.0.0/24 -p all -t 150

# Solo los 5 hosts más críticos
sudo python3 pivotx.py -n 192.168.1.0/24 --top 5

# Sin banner grabbing (más silencioso)
sudo python3 pivotx.py -n 192.168.1.0/24 --no-banner

# Reporte completo en carpeta de pentest
sudo python3 pivotx.py -n 10.0.0.0/16 -p top100 -t 200 --dir /opt/pentests/empresa/ -o fase2_red_interna.html
```

---

## 📊 Presets de Puertos

| Preset | Cantidad de puertos | Velocidad | Ideal para |
|---|---|---|---|
| `pivot` | 35 puertos clave | ⚡ Muy rápido | Reconocimiento inicial enfocado en pivoting |
| `top50` | 50 puertos comunes | ⚡ Rápido | Reconocimiento general rápido |
| `top100` | 1024 + puertos extra | 🔄 Moderado | Escaneo completo para reportes de pentest |
| `all` | 1–9999 | 🐢 Lento | Cobertura total — usar en redes pequeñas |

**Puertos incluidos en el preset `pivot`** (los más relevantes para movimiento lateral):

`21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 161, 389, 443, 445, 636, 1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017`

---

## 🔍 Detección de Pivot

PIVOTX identifica automáticamente oportunidades de pivoting por host según los puertos y servicios detectados:

| Tipo de Host | Detectado por puertos | Vectores de pivot sugeridos |
|---|---|---|
| **Linux / SSH** | 22 | `ssh -D` SOCKS5, Chisel, Ligolo-ng, SSHuttle |
| **Domain Controller** | 88, 389, 636 | Kerberoasting, AS-REP Roasting, Pass-the-Hash, DCSync |
| **Windows Host** | 445, 135, 5985 | SMB/PsExec, WMIExec, Evil-WinRM, CrackMapExec |
| **Dispositivo de Red** | 23, 161 | Telnet enum, SNMP community strings, MIB walk |
| **Base de Datos** | 3306, 1433, 5432, 6379, 27017 | UDF injection, `xp_cmdshell`, RCE via Redis/MongoDB |
| **Servidor Web** | 80, 443, 8080, 8443, 9200 | Web shell upload, reverse shell, LFI/RFI, SSRF |
| **RDP** | 3389 | BlueKeep check, credenciales débiles, pass-the-hash RDP |
| **NFS / Shares** | 2049, 139 | Montaje remoto, lectura de archivos sensibles |
| **VNC** | 5900 | Autenticación débil, captura de pantalla remota |

### Sistema de scoring de riesgo

Cada host recibe un puntaje basado en la criticidad y cantidad de servicios expuestos:

| Nivel | Score | Criterio |
|---|---|---|
| 🔴 **CRITICAL** | 8+ | DC + múltiples vectores, o combinaciones RCE directas |
| 🟠 **HIGH** | 5–7 | SSH + SMB, WinRM expuesto, base de datos accesible |
| 🟡 **MEDIUM** | 3–4 | Uno o dos servicios de administración remota |
| 🟢 **LOW** | 0–2 | Solo servicios web o puertos de bajo riesgo |

---

## 📄 Reporte HTML

El reporte generado incluye:

- **Header ejecutivo** — red objetivo, fecha/hora, duración del escaneo, porcentaje de red escaneada, host más crítico
- **8 métricas clave** — hosts totales, distribución de riesgo (CRITICAL/HIGH/MEDIUM/LOW), exposición de SSH, SMB y RDP
- **Mapa de red interactivo** — nodos arrastrables con hover para detalles, coloreados por nivel de riesgo, construido con D3.js o similar
- **Gráfico de barras de puertos** — top 10 puertos encontrados en toda la red (Chart.js)
- **Tabla de hosts expandible** — cada fila expande para mostrar: puertos abiertos, banners capturados y **comandos copy-paste listos para usar**
- **Cadena de pivot sugerida** — top 5 hosts rankeados por score de pivoting con ruta recomendada

### Ejemplo de comandos generados por host

Para un host con SSH (22) y SMB (445) detectados, el reporte incluirá automáticamente:

```bash
# SSH Tunnel / SOCKS5
ssh -D 1080 -N user@<HOST_IP>

# Chisel (cliente)
chisel client <HOST_IP>:8080 R:socks

# SMB Enum
crackmapexec smb <HOST_IP> -u '' -p ''
smbclient -L //<HOST_IP> -N

# WMI Exec
impacket-wmiexec domain/user:password@<HOST_IP>
```

---

## 💡 Casos de Uso

### Pentest de red interna (fase de reconocimiento)

```bash
# Fase 1: descubrimiento rápido de hosts vivos
sudo python3 pivotx.py -n 10.10.10.0/24 --ping-only

# Fase 2: escaneo completo con reporte
sudo python3 pivotx.py -n 10.10.10.0/24 -p top100 -t 200 --dir /opt/pentest/ -o red_interna.html
```

### CTF / HackTheBox / TryHackMe

```bash
# Red de laboratorio típica
sudo python3 pivotx.py -n 10.10.0.0/16 -p pivot -t 150
```

### Auditoría de red propia

```bash
# Homelab o red corporativa bajo tu administración
sudo python3 pivotx.py -n 192.168.1.0/24 -p all --dir documentos -o auditoria_$(date +%Y%m%d).html
```

### Reconocimiento post-explotación

```bash
# Red interna descubierta desde un host comprometido (con pivoting ya establecido)
sudo python3 pivotx.py -n 172.16.0.0/24 -p pivot --top 10 --no-banner
```

---

## 🛠️ Cómo Funciona

```
┌─────────────────────────────────────────────────────────┐
│  Fase 1 — Descubrimiento                                │
│  ARP sweep si root → respuestas ARP (preciso)           │
│  Ping sweep si no root → ICMP echo (puede omitir hosts) │
├─────────────────────────────────────────────────────────┤
│  Fase 2 — Escaneo de Puertos                            │
│  TCP connect multihilo (configurable)                   │
│  Banner grabbing en puertos abiertos                    │
├─────────────────────────────────────────────────────────┤
│  Fase 3 — Análisis                                      │
│  Scoring de riesgo por host                             │
│  Clasificación de roles (DC, Linux, Windows, DB, etc.)  │
│  Detección de métodos de pivot disponibles              │
│  Generación de comandos específicos por host            │
├─────────────────────────────────────────────────────────┤
│  Fase 4 — Reporte                                       │
│  HTML interactivo (dark theme)                          │
│  Mapa de red con D3.js                                  │
│  Gráficos con Chart.js                                  │
│  Tabla expandible con comandos copy-paste               │
└─────────────────────────────────────────────────────────┘
```

---

## 🐛 Troubleshooting

### `Permission denied` al ejecutar

```bash
# Siempre usar sudo para el modo ARP (recomendado)
sudo python3 pivotx.py -n 192.168.1.0/24
```

### `ModuleNotFoundError: No module named 'scapy'`

```bash
pip3 install scapy netifaces
# o
pip3 install -r requirements.txt
```

### ARP sweep no encuentra hosts

```bash
# Verificar que estás en la red correcta
ip a
ip route

# Probar ping sweep sin root como alternativa
python3 pivotx.py -n 192.168.1.0/24 --ping-only
```

### El escaneo es muy lento

```bash
# Aumentar hilos y usar preset más acotado
sudo python3 pivotx.py -n 192.168.1.0/24 -p pivot -t 200

# Deshabilitar banner grabbing
sudo python3 pivotx.py -n 192.168.1.0/24 --no-banner -t 200
```

### El reporte HTML no abre bien

Abrilo con un navegador moderno (Chrome, Firefox, Edge). No está diseñado para IE o navegadores desactualizados. Verificá que el archivo se guardó correctamente con:

```bash
ls -lh pivotx_report.html
```

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Podés:

- 🐛 **Reportar bugs** abriendo un [Issue](../../issues) con el mensaje de error completo y el comando usado
- 💡 **Sugerir funcionalidades** describiendo el caso de uso en [Issues](../../issues)
- 🔧 **Enviar Pull Requests** — por favor incluí descripción del cambio y, si es posible, tests o evidencia del funcionamiento

### Ideas para futuras versiones

- [ ] Soporte para IPv6
- [ ] Exportación a JSON / CSV
- [ ] Integración con Nmap XML como fuente de datos
- [ ] Modo silencioso (timing configurable para evasión de IDS)
- [ ] Detección de servicios por fingerprinting de respuesta TCP
- [ ] Soporte para autenticación SSH y enumeración post-login

---

## ⚠️ AVISO LEGAL / LEGAL NOTICE

---

### 🇦🇷🇪🇸🇲🇽 AVISO LEGAL (Español)

#### 1. Propósito y alcance

PIVOTX es una herramienta de seguridad informática desarrollada con fines **exclusivamente educativos y de investigación en ciberseguridad**. Está destinada a profesionales de seguridad, investigadores, administradores de sistemas y estudiantes que operen en entornos **legalmente autorizados**, tales como:

- Redes propias o bajo administración directa del usuario
- Laboratorios de práctica y entornos virtuales aislados (CTF, homelab, rangos de entrenamiento)
- Compromisos de prueba de penetración (*pentest*) respaldados por un **contrato escrito firmado** (SOW / Rules of Engagement) que delimite explícitamente el alcance, los sistemas objetivo y las fechas de autorización

#### 2. Requisito de autorización

**El uso de esta herramienta sobre cualquier sistema, red o infraestructura que no sea de tu propiedad requiere autorización previa, explícita y por escrito del propietario legítimo o del responsable legal del sistema objetivo.**

Una autorización verbal, implícita o ambigua **no es suficiente** y no exime de responsabilidad legal. La autorización debe:

- Identificar de forma específica los sistemas y rangos de red autorizados
- Establecer el período de tiempo durante el cual el escaneo o análisis está permitido
- Estar firmada por una persona con capacidad legal para otorgar dicha autorización

#### 3. Marco legal aplicable

El escaneo, acceso o intrusión no autorizados en sistemas informáticos puede constituir un **delito penal** en múltiples jurisdicciones, incluyendo pero no limitado a:

| País / Región | Normativa aplicable |
|---|---|
| 🇦🇷 Argentina | Ley 26.388 (art. 153bis, 197, 255 CP) — Delitos informáticos |
| 🇪🇸 España | Art. 197bis, 264 y ss. del Código Penal |
| 🇲🇽 México | Art. 211bis1–211bis7 del Código Penal Federal |
| 🇺🇸 Estados Unidos | Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 |
| 🇬🇧 Reino Unido | Computer Misuse Act 1990 |
| 🇧🇷 Brasil | Lei 12.737/2012 (Lei Carolina Dieckmann), art. 154-A CP |
| 🇨🇱 Chile | Ley 19.223 sobre delitos informáticos |
| 🇨🇴 Colombia | Ley 1273/2009 — Delitos informáticos |
| 🇺🇾 Uruguay | Ley 18.331 y art. 5 Ley 18.719 |
| 🇵🇪 Perú | Ley 30096 — Delitos informáticos |
| 🇪🇺 Unión Europea | Directiva 2013/40/UE sobre ataques contra sistemas de información |

El usuario es el único responsable de conocer y cumplir la legislación aplicable en su jurisdicción.

#### 4. Descargo de responsabilidad del autor

El autor y colaboradores de PIVOTX:

- **No se hacen responsables** de ningún daño directo, indirecto, incidental, especial o consecuente derivado del uso o mal uso de esta herramienta
- **No garantizan** que el uso de la herramienta sea legal en tu jurisdicción
- **No proporcionan asesoramiento jurídico** de ningún tipo. Para determinar la legalidad de un uso concreto, consultá un abogado especializado en derecho informático o ciberseguridad
- **No respaldan ni autorizan** ningún uso ofensivo, no autorizado o malintencionado
- La distribución de este software bajo licencia MIT **no constituye licencia ni autorización** para realizar actividades ilegales

#### 5. Prohibición expresa de uso malicioso

Queda **expresamente prohibido** el uso de PIVOTX para:

- Escanear, mapear o acceder a sistemas ajenos sin autorización escrita previa
- Realizar reconocimiento con fines de ataque, sabotaje, espionaje o extorsión
- Eludir controles de seguridad en sistemas de terceros
- Cualquier actividad que constituya un delito en la jurisdicción del usuario o del sistema objetivo

El incumplimiento de esta prohibición es responsabilidad exclusiva del usuario.

#### 6. Aceptación de términos

**El uso de esta herramienta implica la aceptación de todos los términos de este aviso legal.** Si no aceptás estas condiciones, no estás autorizado a usar, copiar, distribuir ni modificar este software.

---

### 🇺🇸🇬🇧🇦🇺 LEGAL NOTICE (English)

#### 1. Purpose and Scope

PIVOTX is a cybersecurity tool developed **exclusively for educational and authorized security research purposes**. It is intended for security professionals, researchers, system administrators, and students operating in **legally authorized environments**, such as:

- Networks owned or directly administered by the user
- Isolated practice labs and virtual environments (CTF, homelab, training ranges)
- Penetration testing engagements supported by a **signed written contract** (SOW / Rules of Engagement) that explicitly defines scope, target systems, and authorization dates

#### 2. Authorization Requirement

**Using this tool against any system, network, or infrastructure that you do not own requires prior, explicit, written authorization from the legitimate owner or legal representative of the target system.**

Verbal, implied, or ambiguous authorization is **not sufficient** and does not provide legal protection. Authorization must:

- Specifically identify the authorized systems and network ranges
- Define the time period during which scanning or analysis is permitted
- Be signed by a person with legal authority to grant such authorization

#### 3. Applicable Legal Framework

Unauthorized scanning, access, or intrusion into computer systems may constitute a **criminal offense** in multiple jurisdictions, including but not limited to:

| Country / Region | Applicable Law |
|---|---|
| 🇺🇸 United States | Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 |
| 🇬🇧 United Kingdom | Computer Misuse Act 1990 |
| 🇪🇺 European Union | Directive 2013/40/EU on attacks against information systems |
| 🇦🇺 Australia | Criminal Code Act 1995, Part 10.7 |
| 🇨🇦 Canada | Criminal Code, ss. 342.1, 430(1.1) |
| 🇩🇪 Germany | § 202a–202d, 303a–303b StGB |
| 🇫🇷 France | Articles 323-1 to 323-7 of the Penal Code |
| 🇯🇵 Japan | Unauthorized Computer Access Law (Law No. 128 of 1999) |

Users are solely responsible for understanding and complying with the laws applicable in their jurisdiction.

#### 4. Disclaimer of Liability

The author and contributors of PIVOTX:

- **Are not liable** for any direct, indirect, incidental, special, or consequential damages resulting from the use or misuse of this tool
- **Do not warrant** that use of this tool is legal in your jurisdiction
- **Do not provide legal advice** of any kind. To determine the legality of a specific use case, consult a lawyer specializing in cybersecurity or computer law
- **Do not endorse or authorize** any offensive, unauthorized, or malicious use
- Distribution of this software under the MIT license **does not constitute a license or authorization** to engage in illegal activities

#### 5. Prohibited Uses

The following uses of PIVOTX are **expressly prohibited**:

- Scanning, mapping, or accessing third-party systems without prior written authorization
- Conducting reconnaissance for the purpose of attack, sabotage, espionage, or extortion
- Circumventing security controls on systems belonging to others
- Any activity that constitutes a criminal offense in the jurisdiction of the user or of the target system

Violation of these prohibitions is the sole responsibility of the user.

#### 6. Acceptance of Terms

**By using this tool, you acknowledge that you have read, understood, and agreed to all terms of this legal notice.** If you do not agree to these terms, you are not authorized to use, copy, distribute, or modify this software.

---

> **Este aviso legal reemplaza y deja sin efecto cualquier disclaimer anterior incluido en este repositorio.**
> *Última actualización: Febrero 2026*

---

## 📝 Licencia

Este proyecto está bajo la **Licencia MIT** — consultá el archivo [LICENSE](./LICENSE) para más detalles.

La Licencia MIT aplica únicamente al código fuente. **No autoriza ni licencia actividades ilegales.** Ver el Aviso Legal completo arriba.

---

<div align="center">

Hecho con 🔥 para la comunidad de seguridad informática

⭐ **Si PIVOTX te fue útil, dejá una estrella** ⭐

*Usalo con responsabilidad. Usalo con autorización.*

</div>
