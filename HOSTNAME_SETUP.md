# Hostname profile without Cloudflare

Use `smartdns-installer-hostname.sh` for a provider-managed hostname with an existing Certbot webroot certificate. The upstream `smartdns-installer-v2.10.0-stealth.sh` remains available for the Cloudflare workflow. DNS changes remain the responsibility of the hostname provider.

## Inputs and read-only validation

```bash
sudo env PROVIDER_HOSTNAME='dns.example.net' PUBLIC_IPV4='192.0.2.25' \
  SCRIPT_LANG=en ./smartdns-installer-hostname.sh --hostname-check
```

Replace the example hostname and documentation IP with your values. Interactive runs prompt for missing required values; noninteractive runs fail clearly. The hostname and IP have no built-in server-specific defaults.

| Variable | Purpose / default |
| --- | --- |
| `PROVIDER_HOSTNAME` | Required hostname, also used for ROOT_DOMAIN and DOT_HOST |
| `PUBLIC_IPV4` | Required public VPS IPv4 |
| `PUBLIC_IPV6` | Optional public IPv6; empty disables IPv6 for a new profile |
| `HOSTNAME_CERT_LINEAGE` | `/etc/letsencrypt/live/$PROVIDER_HOSTNAME` |
| `HOSTNAME_ACME_WEBROOT` | `/var/www/$PROVIDER_HOSTNAME` |
| `HOSTNAME_RENEWAL_CONF` | `/etc/letsencrypt/renewal/<lineage-name>.conf` |

The read-only check validates public A/AAAA records, hostname coverage, certificate lifetime, matching key, trusted chain and Certbot webroot settings. An existing certificate must already be available; this profile does not issue an initial certificate.

## Integrate existing Xray and AdGuard

If AdGuard already provides DoH and DoT, reuse those endpoints:

```bash
sudo env PROVIDER_HOSTNAME='dns.example.net' PUBLIC_IPV4='192.0.2.25' \
  SCRIPT_LANG=en ./smartdns-installer-hostname.sh --integrate-existing
```

Keep `smartdns-existing.py` beside the installer. This mode requires an existing Xray REALITY listener on 443 with a PROXY-v1 UNIX-socket fallback, and AdGuard with a working single-host TLS certificate. It preserves REALITY client credentials, routing, listener ports, AdGuard TLS settings, existing filter subscriptions and user rules.

The helper adds a separate unprivileged UNIX-socket SNI relay, managed AdGuard rewrite rules for the GeoHideDNS target list, and an exact secret `/auth/<token>` location in the existing Nginx hostname server. AdGuard continues to handle DoH/DoT. Target domains resolve to the VPS; their AAAA and HTTPS/SVCB responses are suppressed. The relay forwards TLS without decrypting it only for authorized client IPs and allowed domain suffixes. Destination IPs are resolved independently and must be public, excluding the VPS itself. ECH must be disabled for target domains so their SNI remains available.

Open the private authorization URL **from the same network that uses AdGuard DNS**. Authorization lasts 24 hours and survives relay restarts until it expires. Clients using a different egress IP, such as a VPN or mobile network, must authorize that IP separately. Only requests for the managed target domains require this authorization; existing DNS endpoints and other domains retain their previous behavior.

```bash
sudo cat /var/lib/smartdns-existing/connection-info.txt
```

Configuration copies are stored under `/var/backups/smartdns-existing/`. Activation validates proposed Xray/AdGuard/Nginx configurations before restarting Xray and AdGuard briefly. Failed activation restores original configurations. It also verifies existing DoH/DoT, target A rewrites, AAAA/HTTPS suppression, authorized target TLS and unauthenticated rejection. Service dependencies start Nginx and the relay before Xray after reboot; no reboot is performed during installation.

Optional overrides: `XRAY_CONFIG`, `ADGUARD_CONFIG`, `NGINX_SITE`, and `SMARTDNS_DOMAINS_FILE` (a local domain/hosts list instead of the default GeoHideDNS URL). The installer does not run the upstream package/binary installers in integration mode.

Rollback:

```bash
sudo python3 /usr/local/libexec/smartdns-existing.py --rollback
```

## Full installation on a fresh VPS

```bash
sudo env PROVIDER_HOSTNAME='dns.example.net' PUBLIC_IPV4='192.0.2.25' \
  SCRIPT_LANG=en ./smartdns-installer-hostname.sh --install
```

The full installer owns the Xray/Nginx/DNS configuration. It stops with exit code 2 if an unmanaged existing service occupies a required port. This expected refusal does not produce a misleading critical-error traceback. Use `--integrate-existing` for the compatible existing stack described above.

After installation, validated inputs are saved in the root-only settings file. Maintenance commands and the Certbot renewal hook use those saved values. Explicit IP inputs override saved IP values; repeated hostname input retains custom saved paths unless overridden. Changing an installed hostname requires a separate migration.

Client endpoints are `https://<hostname>/resolve/<secret>`, `https://<hostname>/auth/<secret>` and DoT `<hostname>:853`. The same hostname serves both protocols; DoT IP authorization is enabled by default because the SNI hostname is public. Authorize through the secret DoH or Web-Auth endpoint first.

The generated Nginx configuration preserves the HTTP-01 challenge path. A future full installation adds a lineage-specific Certbot deployment hook without replacing existing hooks. The hook reads the configured hostname and certificate lineage from saved settings and restores previous certificate files if Nginx validation or reload fails.

## Validation

```bash
bash -n smartdns-installer-hostname.sh
shellcheck -S warning -e SC1090,SC2034,SC2154 smartdns-installer-hostname.sh
python3 tests/test_hostname_profile.py
python3 -m unittest discover -s tests -p test_existing_integration.py -v
```

The default Python suite isolates saved settings in a temporary directory, mocks DNS and occupied ports, and checks input validation, interactive entry, saved overrides, wizard behavior, renewal-hook syntax and noninteractive help. It does not install services or contact a live DNS zone. Optional live certificate checks can be enabled with `SMARTDNS_LIVE_TESTS=1` and the actual hostname/IP inputs; these require read access to the certificate and private key.
