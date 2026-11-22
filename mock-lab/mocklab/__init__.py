"""NetCommand Mock Cisco SSH Lab.

A small, local SSH server that imitates the text interface of a few Cisco-like
devices, so NetCommand (and Netmiko's cisco_ios driver) can be tested without
real equipment. It is written from scratch in Python: it contains no Cisco
software and only simulates a limited set of commands (see README.md).

    device.py   the simulated configuration of one device and its show output
    cli.py      the command line: modes, prompts, parsing, error messages
    server.py   the SSH server (Paramiko), one listener per device, failure modes
    lab.py      loading lab_config.json, start / stop / status
    restore_sim.py  simulated flash, Tcl/SCP transfer, archive, configure replace with a
                timed rollback on a simulated clock, and restore failure scenarios
"""
