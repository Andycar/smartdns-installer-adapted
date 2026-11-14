

\# Unified SmartDNS + Transparent SNI Proxy



\*\*Version:\*\* 2.10.0-stealth



A unified Bash installer for deploying SmartDNS and Transparent SNI Proxy infrastructure on Debian and Ubuntu servers.



\## Features



\- Automated installation and configuration of the network stack.

\- Support for OxiDNS and AdGuard Home DNS backends.

\- Transparent SNI Proxy integration with Xray.

\- DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT).

\- TLS certificate management.

\- GeoHide DNS integration.

\- Domain-based routing and filtering.

\- Firewall and network configuration.

\- Automatic configuration backups and rollback.

\- Transaction-based installation and updates.

\- Diagnostic and functional testing tools.



\## Supported operating systems



\- Debian 12

\- Debian 13 (Trixie)

\- Ubuntu 22.04 LTS

\- Ubuntu 24.04 LTS



\## Requirements



\- Root access.

\- A supported Linux distribution.

\- A public IPv4 address.

\- A registered domain name.

\- Access to configure DNS records.

\- Internet connectivity.



\## Installation



Download the installer:



```bash

wget -O smartdns-installer.sh \\

https://raw.githubusercontent.com/EvgenyElizarenko/smartdns-installer/main/smartdns-installer-v2.10.0-stealth.sh

```



Make it executable:



```bash

chmod +x smartdns-installer.sh

```



Check server compatibility:



```bash

sudo ./smartdns-installer.sh --preflight

```



Start interactive installation:



```bash

sudo ./smartdns-installer.sh --install

```



\## Available commands



| Command | Description |

|---|---|

| `--help` | Display help |

| `--preflight` | Check server readiness |

| `--install` | Full interactive installation |

| `--switch-engine` | Switch DNS backend |

| `--sync-ip` | Synchronize server IP |

| `--change-domain` | Change the main domain |

| `--update` | Update components and lists |

| `--regenerate-cover` | Regenerate Cover Site |

| `--status` | Show service status |

| `--test` | Run functional tests |

| `--backup` | Create a configuration backup |

| `--rollback` | Restore the latest backup |

| `--uninstall` | Remove installed components |



\## DNS backends



Two DNS engines are supported:



\- OxiDNS

\- AdGuard Home



The DNS engine is selected during installation.



\## Disclaimer



This software modifies system networking, firewall rules, DNS services, proxy configuration and TLS certificates.



Use it only on servers you own or are authorized to administer.



Always review the configuration and maintain an independent backup before installation.



\## Version



Current release: `2.10.0-stealth`

