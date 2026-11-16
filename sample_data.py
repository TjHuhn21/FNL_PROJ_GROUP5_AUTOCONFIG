"""Fake devices, links, and configs for demo mode. SAMPLE DATA, not a real network."""
DEVICES = [
    {'name': 'CORE', 'ip': '192.168.1.2', 'mac': '', 'type': 'switch', 'managed': True, 'status': 'up'},
    {'name': 'SW1', 'ip': '192.168.1.3', 'mac': '', 'type': 'switch', 'managed': True, 'status': 'up'},
    {'name': 'SW2', 'ip': '192.168.1.4', 'mac': '', 'type': 'switch', 'managed': True, 'status': 'up'},
    {'name': 'R1', 'ip': '192.168.1.1', 'mac': '', 'type': 'router', 'managed': True, 'status': 'up'},
    {'name': 'AP-1', 'ip': '192.168.1.9', 'mac': '', 'type': 'unknown', 'managed': False, 'status': 'up'},
]

LINKS = [
    ('CORE', 'Gi0/1', 'SW1', 'Gi0/1'),
    ('CORE', 'Gi0/2', 'SW2', 'Gi0/1'),
    ('CORE', 'Gi0/3', 'R1', 'Gi0/0'),
    ('SW2', 'Fa0/5', 'AP-1', 'eth0'),
]

# Invented running-configs with deliberate mistakes for the review rules.
CONFIGS = {
    # Telnet allowed, no password encryption, one access port without port security
    'SW1': """hostname SW1
!
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
line vty 0 4
 transport input all
!
""",
    # Encryption on, SSH only, but a trunk allows every VLAN and a port is unsecured
    'SW2': """hostname SW2
service password-encryption
!
interface FastEthernet0/2
 switchport mode access
 switchport port-security
!
interface FastEthernet0/3
 switchport mode access
!
interface GigabitEthernet0/1
 switchport mode trunk
!
line vty 0 4
 transport input ssh
!
""",
}
