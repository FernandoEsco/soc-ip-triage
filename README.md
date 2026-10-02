# IP Reputation Check

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencias](https://img.shields.io/badge/dependencias-ninguna-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**Script de línea de comandos que consulta la reputación de una dirección IP en [AbuseIPDB](https://www.abuseipdb.com) y [VirusTotal](https://www.virustotal.com) al mismo tiempo y entrega un veredicto en la misma terminal.**

Pensado para el día a día de un analista SOC: llega una alerta con una IP sospechosa, ejecutas un solo comando y en segundos sabes si es maliciosa, quién la opera, desde dónde y por qué la han reportado. Ya no tienes que abrir dos sitios ni copiar y pegar entre pestañas.

```bash
python ip_check.py 185.220.101.1
```

---

## Contenido

- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Configuración de las API keys](#configuración-de-las-api-keys)
- [Uso](#uso)
- [Ejemplo de salida](#ejemplo-de-salida)
- [Cómo se calcula el veredicto](#cómo-se-calcula-el-veredicto)
- [Códigos de salida](#códigos-de-salida)
- [Manejo de errores](#manejo-de-errores)
- [Seguridad](#seguridad)
- [Límites de las APIs gratuitas](#límites-de-las-apis-gratuitas)

---

## Características

- **Un solo argumento.** Solo le pasas la IP; las llaves se leen de variables de entorno o de un archivo `.env`.
- **Consultas en paralelo.** AbuseIPDB y VirusTotal se consultan al mismo tiempo, así que la respuesta llega en el tiempo de la más lenta y no en la suma de ambas.
- **Veredicto combinado.** El resultado es ✖ MALICIOSA, ⚠ SOSPECHOSA o ✔ LIMPIA, siempre con los motivos que lo justifican.
- **Contexto útil para el análisis:**
  - **AbuseIPDB:** confianza de abuso, número de reportes y de usuarios que reportaron, ISP, dominio, tipo de uso (hosting, ISP, etc.), país, si es nodo Tor y las categorías de ataque más reportadas.
  - **VirusTotal:** detecciones por motor, nombres de los motores que la detectan, reputación, votos de la comunidad, ASN y propietario, red y etiquetas.
- **Acepta IPs "defangeadas".** Puedes pegar `185.220.101[.]1` tal como viene en un ticket o reporte.
- **Soporta IPv4 e IPv6**, y avisa si la IP es privada o reservada.
- **Salida en color**, que se desactiva sola al redirigir a un archivo o con `NO_COLOR`.
- **Tolerante a fallos.** Si una fuente falla (cuota agotada, llave inválida, sin conexión), muestra la otra y marca el veredicto como parcial.
- **Cero dependencias.** Solo usa la librería estándar de Python, así que no hay que instalar nada con `pip`.

## Requisitos

- Python **3.8 o superior**
- Una API key gratuita de cada servicio (con una sola el script también funciona):
  - AbuseIPDB: crea una cuenta y entra a [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)
  - VirusTotal: crea una cuenta y entra a tu perfil, sección **API Key**

## Instalación

```bash
git clone https://github.com/FernandoEsco/ip-reputation-check.git
cd ip-reputation-check
```

No hay paso de instalación. El script está listo para usarse.

## Configuración de las API keys

Las llaves **nunca** se escriben en el código. Elige una de estas dos opciones:

### Opción A: archivo `.env` (recomendada)

Copia la plantilla y pega tus llaves:

```bash
cp .env.example .env
```

```dotenv
ABUSEIPDB_API_KEY=tu_llave_de_abuseipdb
VT_API_KEY=tu_llave_de_virustotal
```

El script busca el `.env` en su propia carpeta y en el directorio desde donde lo ejecutas.

### Opción B: variables de entorno

**Linux / macOS**. Para que sea permanente, agrégalo a `~/.bashrc` o `~/.zshrc`:

```bash
export ABUSEIPDB_API_KEY="tu_llave"
export VT_API_KEY="tu_llave"
```

**Windows (PowerShell)**. Es permanente, pero tienes que abrir una terminal nueva para que surta efecto:

```powershell
setx ABUSEIPDB_API_KEY "tu_llave"
setx VT_API_KEY "tu_llave"
```

> Si una variable existe en el entorno y también en el `.env`, gana la del entorno.

## Uso

```bash
python ip_check.py <IP>
```

```bash
python ip_check.py 185.220.101.1          # IPv4
python ip_check.py 185.220.101[.]1        # IP defangeada
python ip_check.py 2001:4860:4860::8888   # IPv6
python ip_check.py --help                 # ayuda
```

En Linux o macOS también puedes ejecutarlo directamente:

```bash
chmod +x ip_check.py
./ip_check.py 185.220.101.1
```

## Ejemplo de salida

*(datos ficticios)*

```text
Consultando reputación de 203.0.113.7 …

▌ AbuseIPDB
  Confianza de abuso:              100%
  Reportes (90 días):              1523 de 412 usuarios distintos
  Último reporte:                  2026-10-01 22:14 UTC
  ISP:                             Example Hosting
  Dominio:                         example.test
  Tipo de uso:                     Data Center/Web Hosting/Transit
  País:                            Germany (DE)
  Hostnames:                       tor-exit.example.test
  Nodo Tor / Whitelist:            Sí / No
  Categorías más reportadas:       Brute-Force (2), SSH (1), Port Scan (1), Hacking (1)

▌ VirusTotal
  Detecciones:                     14 maliciosa · 2 sospechosa · 55 inofensiva · 23 sin detección (de 94)
  Reputación:                      -42
  Votos comunidad:                 9 maliciosa / 1 inofensiva
  ASN / Propietario:               AS64496 — Example AS
  Red:                             203.0.113.0/24
  País:                            DE
  Último análisis:                 2026-09-21 14:13 UTC
  Etiquetas:                       tor
  Motores que la detectan:         EngineA (malware), EngineB (suspicious)

════════════════════════════════════════════════════════════════
  VEREDICTO para 203.0.113.7:  ✖ MALICIOSA
   • AbuseIPDB: confianza de abuso 100% (1523 reportes)
   • VirusTotal: 14/94 motores la marcan como maliciosa
════════════════════════════════════════════════════════════════
  Enlaces:
   https://www.abuseipdb.com/check/203.0.113.7
   https://www.virustotal.com/gui/ip-address/203.0.113.7
```

## Cómo se calcula el veredicto

El veredicto final es el **más severo** que indique cualquiera de las dos fuentes:

| Veredicto | AbuseIPDB | VirusTotal |
|---|---|---|
| ✖ **MALICIOSA** | Confianza de abuso **≥ 75%** | **≥ 5** motores la marcan como maliciosa |
| ⚠ **SOSPECHOSA** | Confianza **≥ 25%**, o **≥ 10** reportes aunque la confianza sea baja | **≥ 1** motor la marca como maliciosa, o **≥ 3** como sospechosa |
| ✔ **LIMPIA** | Por debajo de lo anterior | Por debajo de lo anterior |
| ? **SIN DATOS** | Ninguna fuente respondió | |

Los umbrales son constantes al inicio del script, así que puedes ajustarlos al criterio de tu equipo:

```python
ABUSE_MALICIOSA, ABUSE_SOSPECHOSA = 75, 25
VT_MALICIOSA, VT_SOSPECHOSA = 5, 1
MAX_AGE_DAYS = 90   # ventana de reportes consultada en AbuseIPDB
```

> El veredicto es una **ayuda para el triage**, no un sustituto del análisis. Una IP "limpia" puede ser infraestructura nueva de un atacante, y una "maliciosa" puede ser una IP compartida (CDN, VPN, NAT de un ISP). Revisa siempre el contexto.

## Códigos de salida

El código de salida refleja el veredicto, así que el script se puede usar dentro de otros scripts o en automatizaciones:

| Código | Significado |
|---|---|
| `0` | Limpia |
| `1` | Sospechosa |
| `2` | Maliciosa |
| `3` | Error (IP inválida, sin llaves o ninguna fuente respondió) |

Ejemplo en Bash:

```bash
python ip_check.py "$IP" > /dev/null
[ $? -eq 2 ] && echo "$IP" >> bloquear.txt
```

## Manejo de errores

| Situación | Comportamiento |
|---|---|
| IP inválida | Mensaje claro y código `3` |
| IP privada o reservada (`10.x`, `192.168.x`…) | Aviso; la consulta se hace de todos modos |
| Falta una de las llaves | Esa fuente se marca como *omitida* y se usa la otra |
| Faltan las dos llaves | Mensaje con instrucciones y código `3` |
| Llave inválida (401/403) | Se indica en la sección de esa fuente |
| Cuota agotada (429) | Se indica, y el veredicto se marca como *parcial* |
| IP sin registros en VirusTotal | Cuenta como "sin detecciones", no como error |
| Sin conexión o timeout (20 s) | Se indica, y se muestra lo que haya respondido la otra fuente |

## Seguridad

- Las llaves se leen del entorno o de `.env`; **nunca** están escritas en el código.
- El `.gitignore` excluye `.env`. Antes de hacer *commit*, confirma con `git status` que no aparezca.
- Las llaves se envían únicamente por *headers* HTTPS a las APIs oficiales y no se imprimen en pantalla.

Contenido recomendado para `.gitignore`:

```gitignore
.env
__pycache__/
```

## Límites de las APIs gratuitas

| Servicio | Límite del plan gratuito (aprox.) |
|---|---|
| AbuseIPDB | 1,000 consultas `check` al día |
| VirusTotal | 4 consultas por minuto y 500 al día; **no permite uso comercial** |

Los límites pueden cambiar; consulta la documentación de cada servicio. Si vas a usar el script en un entorno corporativo, revisa los términos de VirusTotal: el plan gratuito no permite uso comercial.

## Estructura del proyecto

```
ip-reputation-check/
├── ip_check.py      # Script principal
├── .env.example     # Plantilla para las API keys
├── .gitignore
├── LICENSE
└── README.md
```

## Aviso

Proyecto independiente, sin relación con AbuseIPDB ni con VirusTotal y sin su aval. Su uso está sujeto a los términos de servicio de cada plataforma.

## Licencia
Fernando Escobar
[MIT](LICENSE)
