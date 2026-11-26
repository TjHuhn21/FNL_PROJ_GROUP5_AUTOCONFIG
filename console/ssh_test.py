"""Test an SSH login over the network to a device that was just set up through its
console (Initial Setup page, step 6).

    ok, message = test_ssh_login('192.168.1.1', 'admin', password)

It logs in with the same SSH settings as every other NetCommand connection
(ssh_options.connect_options: strict algorithms; the old SHA-1 ones only for the addresses in
NETCOMMAND_LEGACY_SSH_HOSTS), reads the prompt, and logs out. Nothing is configured.

This is a test of a newly set-up device, so it does NOT count toward the failed device
login lockout (the caller logs it to the Console). The messages are fixed texts: never the
exception's own text, never the password.
"""
import ssh_options

TEST_TIMEOUTS = {'conn_timeout': 10, 'auth_timeout': 15, 'banner_timeout': 15}

OK_TEXT = 'SSH login OK'
TIMEOUT_TEXT = ('No answer from {host} (timed out): check the PC\'s network settings (IP '
                'address in the same subnet), the cable to the device, and the management IP.')
AUTH_TEXT = ('The device refused the login (authentication failed): check the username and '
             'password.')
REFUSED_TEXT = ('Connection refused by {host}: SSH is not accepting connections (check "show ip '
                'ssh" and "transport input ssh" on the VTY lines).')
ALGORITHMS_TEXT = 'The SSH login failed: {detail} (for example {host}), then test again.'
OTHER_TEXT = 'The SSH login failed: {detail}.'


def test_ssh_login(host, username, password, connect=None):
    """(ok, message). connect: the ConnectHandler to use (tests replace it)."""
    if connect is None:
        from netmiko import ConnectHandler as connect
    conn = None
    try:
        conn = connect(device_type='cisco_ios', host=host, username=username, password=password,
                       **TEST_TIMEOUTS, **ssh_options.connect_options(host))
        prompt = conn.find_prompt()
        return True, f'{OK_TEXT}: {username}@{host}, prompt {prompt}'
    except Exception as err:
        kind, detail = ssh_options.describe_error(err, host)
        text = {ssh_options.TIMEOUT: TIMEOUT_TEXT, ssh_options.AUTH: AUTH_TEXT,
                ssh_options.REFUSED: REFUSED_TEXT,
                ssh_options.ALGORITHMS: ALGORITHMS_TEXT}.get(kind, OTHER_TEXT)
        return False, text.format(host=host, detail=detail)
    finally:
        password = None
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
