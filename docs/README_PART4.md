# Part 4: Lab, Testing, Documents, Findings + Topology screens

## Your files
- `README.md`
- `lab/lab_configs.txt`
- `gui/findings_tab.py`
- `gui/topology_tab.py`
- `tests/test_gui.py`
- `sample_data.py`, `conftest.py` (shared by everyone, identical in every package; do not edit)

## Needs from other parts
Part 3 (review/rules.py, topology/graph.py) for both screens; Part 5 (gui/theme.py) for the look; the store (db_fake.py or db.py) for Findings. In practice: unzip this package over the full netcommand project (or your merged branch).

## Run
```
pip install -r requirements.txt
python -m pytest -q tests/test_gui.py   # Windows/Mac
xvfb-run python -m pytest -q tests/test_gui.py              # Linux with no display
python main.py --demo                                       # see your two screens
```

## Done when
The lab passes T1 and T5 on paper (CDP lists the neighbors, planted mistakes are in place), the two screens run on fake data, and the README has the test table.

## Notes
The lab itself (GNS3) cannot be built from code: follow lab/lab_configs.txt, fill the README test table with screenshots, and keep the backup files. tests/test_gui.py is the end-to-end check for the whole path (scan, approve, map, review, configure, logs), so it needs every part present.

Branch name: `part4-...`; open a pull request when your piece works. The lead merges.
