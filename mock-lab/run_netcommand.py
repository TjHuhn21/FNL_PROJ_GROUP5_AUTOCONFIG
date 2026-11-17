"""Start NetCommand for the mock lab, kept apart from your real data.

    python run_netcommand.py          (from the mock-lab folder, while the lab runs)

What is different from `python main.py`, without changing any NetCommand file:
  * the in-memory sample store is used (main.py --demo): the production database
    is never opened, and everything you approve is forgotten when the window closes;
  * configuration backups go to mock-lab/backups/ instead of netcommand/backups/;
  * the saved topology layout goes to mock-lab/state/ instead of %APPDATA%.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)


def main():
    os.makedirs(os.path.join(HERE, 'state'), exist_ok=True)
    os.environ['NETCOMMAND_LAYOUT_FILE'] = os.path.join(HERE, 'state', 'topology_layout.json')
    sys.path.insert(0, PROJECT)
    os.chdir(PROJECT)
    from config import connect
    connect.BACKUP_DIR = os.path.join(HERE, 'backups')          # this process only
    import main as netcommand
    sys.argv = [os.path.join(PROJECT, 'main.py'), '--demo']        # memory store, no monitor
    print('NetCommand (mock lab mode): memory store only; backups in', connect.BACKUP_DIR)
    print('In Scan, untick the sample option, use seed 127.0.0.11 and the lab scan login '
          'from lab_config.json.')
    netcommand.main()


if __name__ == '__main__':
    main()
