"""Start NetCommand for the mock lab, kept apart from your real data.

    python run_netcommand.py              (from the mock-lab folder, while the lab runs)
    python run_netcommand.py --signed-in  (the same, but with the normal sign-in)

Both modes, without changing any NetCommand file or setting:
  * the Initial Setup page uses the mock lab's SIMULATED console ports (main.py
    --mock-console): the computer's real COM ports are never listed or opened;
  * the window title and status bar say "MOCK LAB - simulated devices"
    (NETCOMMAND_MOCK_LAB=1; display only, it changes nothing else);
  * configuration backups go to mock-lab/backups/ instead of netcommand/backups/;
  * the saved topology layout goes to mock-lab/state/ instead of %APPDATA%.

Default mode (main.py --demo --mock-console): the in-memory sample store is used, the
production database is never opened, there is no sign-in, and everything approved is
forgotten when the window closes.

--signed-in (main.py --mock-console): exactly the normal start. Signing in with the email
code goes through the NetCommand backend (NETCOMMAND_API_URL), and the desktop then uses
the database named in .env as always (its sample-mode fallback included). Nothing about
authentication, the backend or the database is changed or skipped here; the backend must
be running. Devices found in the lab are saved in that database like any other.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
MOCK_LAB_VARIABLE = 'NETCOMMAND_MOCK_LAB'      # the same name as gui.main_window's


def netcommand_argv(signed_in=False):
    """The command line main.py is given: --mock-console always, --demo unless signed in."""
    return [os.path.join(PROJECT, 'main.py')] + ([] if signed_in else ['--demo']) + \
        ['--mock-console']


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog='python run_netcommand.py', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--signed-in', action='store_true',
                   help='normal sign-in (backend API, email code) and the database from .env, '
                        'instead of the in-memory sample store')
    return p.parse_args(argv)


def prepare(signed_in=False, environ=None):
    """Sets this process up for the lab and returns main.py's command line."""
    environ = os.environ if environ is None else environ
    os.makedirs(os.path.join(HERE, 'state'), exist_ok=True)
    environ['NETCOMMAND_LAYOUT_FILE'] = os.path.join(HERE, 'state', 'topology_layout.json')
    environ[MOCK_LAB_VARIABLE] = '1'
    if PROJECT not in sys.path:
        sys.path.insert(0, PROJECT)
    from config import connect
    connect.BACKUP_DIR = os.path.join(HERE, 'backups')          # this process only
    return netcommand_argv(signed_in)


def main(argv=None, run=None):
    """run: the NetCommand entry point (tests pass a stand-in; default main.main)."""
    args = parse_args(argv)
    command = prepare(args.signed_in)
    os.chdir(PROJECT)
    if run is None:
        import main as netcommand
        run = netcommand.main
    sys.argv = command
    from config import connect
    print('NetCommand (MOCK LAB - simulated devices):',
          'normal sign-in, database from .env' if args.signed_in else
          'memory store only, no sign-in', '| simulated console ports | backups in',
          connect.BACKUP_DIR)
    print('In Scan, untick the sample option, use seed 127.0.0.11 and the lab scan login '
          'from lab_config.json.')
    run()


if __name__ == '__main__':
    main()
