"""Glue between the tabs and the other parts (kept out of the GUI code)."""
import sample_data


NO_DEVICES = 'No registered devices yet'


def get_network(store, allow_sample=True):
    """(devices, links, source_label).
    With registered devices: those devices and their links ('Registered devices (N)').
    With none: the built-in sample network, clearly labelled SAMPLE DATA, or, when
    allow_sample is False (real database mode), nothing at all, so sample devices
    are never shown as if they were the user's network."""
    devices = store.get_devices('', 'name', 1, 1000)
    if devices:
        return devices, store.get_links(), f'Registered devices ({len(devices)})'
    if not allow_sample:
        return [], [], NO_DEVICES
    return (sample_data.DEVICES, sample_data.LINKS,
            'SAMPLE DATA (no registered devices yet)')


def fetch_configs(store, devices):
    """Read the running-config of every managed device that has a saved login.
    Returns ({name: text}, [notes about devices that were skipped])."""
    from config.connect import get_config
    configs, notes = {}, []
    for d in devices:
        if not d.get('managed'):
            continue
        user, pw = store.get_credentials(d['id'])
        if not user:
            notes.append(f"{d['name']}: no saved login, skipped")
            continue
        try:
            configs[d['name']] = get_config({'host': d['ip'], 'username': user,
                                             'password': pw})
        except Exception as err:
            notes.append(f"{d['name']}: {type(err).__name__}, skipped")
    return configs, notes


def collect_review_inputs(store, demo=False):
    """(devices, links, configs, notes, source_label) for the review.
    Sample mode: the sample configs, labelled SAMPLE DATA.
    Real database mode: the registered devices and their real configs; with
    nothing registered, empty inputs and the NO_DEVICES label, never the sample network."""
    devices, links, source = get_network(store, allow_sample=demo)
    if not devices:
        return [], [], {}, [], source
    if source.startswith('SAMPLE') or demo:
        return (devices, links, sample_data.CONFIGS, [],
                'SAMPLE DATA (demo configs, not read from devices)')
    configs, notes = fetch_configs(store, devices)
    return devices, links, configs, notes, source


def run_discovery(username, password, seed_ip, demo):
    from discovery import crawler
    if demo:
        return crawler.discover_demo()
    return crawler.discover(username, password, seed_ip)
