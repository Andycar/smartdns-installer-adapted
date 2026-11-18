from pathlib import Path
import os
import subprocess
import tempfile

installer = Path(os.environ.get('SMARTDNS_INSTALLER', str(Path(__file__).resolve().parents[1] / 'smartdns-installer-hostname.sh')))
live = os.environ.get('SMARTDNS_LIVE_TESTS') == '1'
os.environ.setdefault('PROVIDER_HOSTNAME', 'dns.example.net')
os.environ.setdefault('PUBLIC_IPV4', '192.0.2.25')
source = installer.read_text()
assert source.count('main "$@"') == 1

with tempfile.TemporaryDirectory(prefix='smartdns-hostname-test-') as folder:
    temp = Path(folder)
    library = temp / 'library.sh'
    library.write_text(source.replace('main "$@"', '').replace(
        'readonly SETTINGS_FILE="${STATE_DIR}/settings"', f'readonly SETTINGS_FILE="{temp}/settings"'))
    prefix = f'source "{library}"\ntrap - ERR\nACTION_MODE=preflight\n'

    def check(label, script, succeeds=True, inputs=None, initialize=True):
        env = dict(os.environ, SCRIPT_LANG='en')
        if inputs is not None:
            for key in ['PROVIDER_HOSTNAME', 'PUBLIC_IPV4', 'PUBLIC_IPV6', 'HOSTNAME_CERT_LINEAGE', 'HOSTNAME_ACME_WEBROOT', 'HOSTNAME_RENEWAL_CONF']:
                env.pop(key, None)
            env.update(inputs)
        setup = 'initialize_hostname_profile\n' if initialize else ''
        result = subprocess.run(['bash', '-c', prefix + setup + script], env=env, capture_output=True, text=True, timeout=20)
        assert (result.returncode == 0) == succeeds, (label, result.returncode, result.stdout, result.stderr)
        print('PASS:', label)
        return result

    generic = {'PROVIDER_HOSTNAME': 'dns.example.net', 'PUBLIC_IPV4': '192.0.2.25'}
    check('generic environment inputs derive all hostname paths', '''
[[ "$ROOT_DOMAIN" == dns.example.net && "$SERVER_IPV4" == 192.0.2.25 ]]
[[ "$HOSTNAME_CERT_LINEAGE" == /etc/letsencrypt/live/dns.example.net ]]
[[ "$HOSTNAME_ACME_WEBROOT" == /var/www/dns.example.net ]]
[[ "$HOSTNAME_RENEWAL_CONF" == /etc/letsencrypt/renewal/dns.example.net.conf ]]
''', inputs=generic)
    check('custom certificate paths and IPv6 accepted', '''
[[ "$HOSTNAME_CERT_LINEAGE" == /etc/letsencrypt/live/custom-name ]]
[[ "$HOSTNAME_RENEWAL_CONF" == /etc/letsencrypt/renewal/custom-name.conf ]]
[[ "$SERVER_IPV6" == 2001:db8::25 ]]
''', inputs=dict(generic, HOSTNAME_CERT_LINEAGE='/etc/letsencrypt/live/custom-name', HOSTNAME_ACME_WEBROOT='/srv/acme', PUBLIC_IPV6='2001:db8::25'))
    check('missing noninteractive inputs rejected', '', False, inputs={})
    check('invalid hostname rejected', '', False, inputs=dict(generic, PROVIDER_HOSTNAME='bad;hostname'))
    check('invalid IPv4 rejected', '', False, inputs=dict(generic, PUBLIC_IPV4='999.0.0.1'))
    check('invalid IPv6 rejected', '', False, inputs=dict(generic, PUBLIC_IPV6='::::'))
    check('unsafe configuration path rejected', '', False, inputs=dict(generic, HOSTNAME_CERT_LINEAGE='/tmp/$(touch bad)'))
    check('selected inputs survive lifecycle settings reload', '''
SERVER_IPV4=198.51.100.1
HOSTNAME_CERT_LINEAGE=/tmp/previous
restore_hostname_profile
[[ "$SERVER_IPV4" == 192.0.2.25 && "$HOSTNAME_CERT_LINEAGE" == /etc/letsencrypt/live/dns.example.net ]]
''', inputs=generic)

    settings = temp / 'settings'
    settings.write_text('ROOT_DOMAIN="dns.example.net"\nSERVER_IPV4="192.0.2.10"\nPROVIDER_HOSTNAME="dns.example.net"\nPUBLIC_IPV4="192.0.2.10"\n')
    check('saved profile usable without repeated environment variables', '[[ "$PROVIDER_HOSTNAME" == dns.example.net && "$PUBLIC_IPV4" == 192.0.2.10 ]]\n', inputs={})
    check('explicit IP overrides saved IP', '[[ "$PUBLIC_IPV4" == 192.0.2.25 ]]\n', inputs=generic)
    with settings.open('a') as file:
        file.write('HOSTNAME_CERT_LINEAGE="/etc/letsencrypt/live/custom-saved"\n')
    check('repeating hostname retains saved custom certificate path', '[[ "$HOSTNAME_CERT_LINEAGE" == /etc/letsencrypt/live/custom-saved ]]\n', inputs=generic)
    check('existing hostname change requires migration', '', False, inputs=dict(generic, PROVIDER_HOSTNAME='other.example.net'))
    settings.unlink()

    # Verify actual terminal input is accepted when the environment is empty.
    import pty
    master, slave = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k not in ['PROVIDER_HOSTNAME', 'PUBLIC_IPV4', 'PUBLIC_IPV6']}
    env['SCRIPT_LANG'] = 'en'
    proc = subprocess.Popen(['bash', '-c', prefix + 'initialize_hostname_profile\n[[ "$PROVIDER_HOSTNAME" == dns.example.net && "$PUBLIC_IPV4" == 192.0.2.25 ]]\n'],
                            stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
    os.close(slave)
    os.write(master, b'dns.example.net\n192.0.2.25\n')
    try:
        stdout, stderr = proc.communicate(timeout=5)
        assert proc.returncode == 0, stderr
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)
    print('PASS: interactive hostname and IPv4 prompts')

    # No root files, services or network changes: a fake reader drives the wizard.
    result = check('wizard uses one hostname and no Cloudflare input', '''
CPU_ARCH=x86_64
IPTABLES_BACKEND=nft
DOCKER_PRESENT=0
read_tr() {
    case "$1" in
        M_0040) printf -v "$2" 2 ;;
        M_0049|M_0081) printf -v "$2" Y ;;
        M_0063|M_0067) printf -v "$2" N ;;
        *) echo "Unexpected prompt: $1" >&2; return 1 ;;
    esac
}
run_interactive_wizard </dev/null
[[ "$ROOT_DOMAIN" == "$PROVIDER_HOSTNAME" && "$DOT_HOST" == "$ROOT_DOMAIN" ]]
[[ "$DOT_WHITELIST_ENABLED" == true && "$DOT_WHITELIST_MODE" == shared ]]
[[ -z "$CF_API_TOKEN" && ${#DOH_PATH} -ge 48 ]]
''')
    profile = 'ROOT_DOMAIN="$PROVIDER_HOSTNAME"\nDOT_HOST="$ROOT_DOMAIN"\n'
    dig_ok = '''dig() { if [[ "${*: -2:1}" == A ]]; then echo "$PUBLIC_IPV4"; fi; }\n'''
    check('provider DNS validation accepts correct A/no AAAA', profile + dig_ok + 'sync_cloudflare_dns_records "$PUBLIC_IPV4"\n')
    check('provider DNS validation rejects wrong A', profile + 'dig() { echo 192.0.2.1; }\nsync_cloudflare_dns_records "$PUBLIC_IPV4"\n', False)
    check('provider DNS validation rejects unexpected AAAA', profile + 'dig() { if [[ "${*: -2:1}" == A ]]; then echo "$PUBLIC_IPV4"; else echo 2001:db8::1; fi; }\nsync_cloudflare_dns_records "$PUBLIC_IPV4"\n', False)
    check('provider DNS validation rejects child DoT name', profile + 'DOT_HOST=dot.$ROOT_DOMAIN\nvalidate_hostname_profile\n', False)
    if live:
        check('existing source certificate validates', 'verify_hostname_source_certificate\n')
    check('provider domain change is blocked', 'run_change_domain example.com\n', False)
    check('real occupied VPS blocks fresh install', 'ss() { echo occupied; }\nassert_fresh_install_target\n', False)

    if live:
        # Extract generated verifier into a temporary file; never install it globally.
        start = source.index("#!/usr/bin/env bash\nset -Eeuo pipefail\n\nCERT_FILE=")
        end = source.index('\nEOF', start)
        verifier = temp / 'verify.sh'
        verifier.write_text(source[start:end])
        def verify(label, cert, key, hostname, succeeds=True):
            r = subprocess.run(['bash', str(verifier), str(cert), str(key), hostname], capture_output=True, text=True, timeout=10)
            assert (r.returncode == 0) == succeeds, (label, r.stderr)
            print('PASS:', label)
        host = os.environ['PROVIDER_HOSTNAME']
        lineage = Path(os.environ.get('HOSTNAME_CERT_LINEAGE', '/etc/letsencrypt/live/' + host))
        verify('single-host certificate accepted without wildcard', lineage / 'fullchain.pem', lineage / 'privkey.pem', host)
        verify('wrong certificate hostname rejected', lineage / 'fullchain.pem', lineage / 'privkey.pem', 'wrong.example.com', False)
        other_key = temp / 'other.key'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(other_key)], check=True, capture_output=True)
        verify('mismatched private key rejected', lineage / 'fullchain.pem', other_key, host, False)

    # Syntax-check the actual generated renewal deploy hook without executing it.
    start = source.index("#!/usr/bin/env bash\nset -Eeuo pipefail\numask 027\n[[ -f /var/lib/oxidns-installer/settings ]]")
    end = source.index('\nHOOK', start)
    hook = temp / 'renew-hook.sh'
    hook.write_text(source[start:end])
    subprocess.run(['bash', '-n', str(hook)], check=True)
    print('PASS: renewal deploy hook syntax')
    # Other certificate lineages must be ignored before accessing system paths.
    subprocess.run(['bash', str(hook)], env=dict(os.environ, RENEWED_LINEAGE='/tmp/other-lineage'), check=True)
    print('PASS: renewal hook ignores other certificate lineages')

    process = subprocess.Popen(['bash', str(installer), '--help'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=dict(os.environ, SCRIPT_LANG='en'), text=True)
    try:
        process.wait(timeout=3)
        assert process.returncode == 0 and 'No Cloudflare account' in process.stdout.read()
    finally:
        if process.poll() is None:
            process.kill()
        process.stdin.close()
    print('PASS: noninteractive hostname-profile help')

    assert 'location ^~ /.well-known/acme-challenge/' in source
    assert '--dns dns_cf' not in source and 'cf_resolve_zone' not in source
    print('PASS: HTTP-01 route retained; Cloudflare API flow removed')
    assert '213.21.253.61' not in source
    print('PASS: no VPS-specific hostname or IP literals in installer')

    # The actual ERR trap must not turn an expected occupied-port refusal into
    # a critical installation error. Nothing after the guard may run.
    script = f'''source "{library}"
check_root() {{ :; }}
acquire_lock() {{ :; }}
detect_environment() {{ :; }}
validate_os_and_resources() {{ :; }}
ss() {{ if [[ "$*" == *":443"* ]]; then echo LISTEN; fi; }}
hostname_check() {{ echo UNEXPECTED_MUTATION >&2; exit 99; }}
main --install
'''
    result = subprocess.run(['bash', '-c', script], env=dict(os.environ, SCRIPT_LANG='en'),
                            input='', text=True, capture_output=True, timeout=5)
    assert result.returncode == 2 and 'port 443' in result.stderr, result.stderr
    assert 'Critical execution error' not in result.stderr and 'UNEXPECTED_MUTATION' not in result.stderr
    print('PASS: occupied port is an expected refusal, without ERR-trap noise or mutations')

    helper = temp / 'smartdns-existing.py'
    helper.write_text('import sys; print("HELPER_ARGS=" + " ".join(sys.argv[1:]))')
    dispatch = f'''source "{library}"
check_root() {{ :; }}
acquire_lock() {{ :; }}
'''
    for arguments in ['--integrate-existing', '--integrate-existing --no-authorization', '--no-authorization --integrate-existing']:
        result = subprocess.run(['bash', '-c', dispatch + 'main ' + arguments],
                                env=dict(os.environ, SCRIPT_LANG='en'), input='', text=True, capture_output=True, timeout=5)
        expected = 'HELPER_ARGS=--install' + (' --no-authorization' if '--no-authorization' in arguments else '')
        assert result.returncode == 0 and expected in result.stdout, (arguments, result.stderr, result.stdout)
    result = subprocess.run(['bash', '-c', dispatch + 'main --install --no-authorization'],
                            env=dict(os.environ, SCRIPT_LANG='en'), input='', text=True, capture_output=True, timeout=5)
    assert result.returncode == 2 and 'applies only to integration mode' in result.stderr, result.stderr
    print('PASS: no-authorization flag forwarding, either argument order, default policy and invalid-mode rejection')
