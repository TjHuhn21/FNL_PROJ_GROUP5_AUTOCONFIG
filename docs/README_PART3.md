# Part 3: Config Review, Topology Map, Command Builders

## Your files
- `review/__init__.py`
- `review/rules.py`
- `topology/__init__.py`
- `topology/graph.py`
- `config/__init__.py`
- `config/commands_switch.py`
- `config/commands_router.py`
- `tests/test_part3.py`
- `sample_data.py`, `conftest.py` (shared by everyone, identical in every package; do not edit)

## Needs from other parts
Nothing. This part is plain Python on data and runs on its own.

## Run
```
pip install networkx matplotlib pytest
python -m pytest -q          # 10 tests
```

## Done when
Four rules work on sample config text and return nothing on a clean config; review_network returns a score; draw_map saves a PNG; build_commands gives the right text for 3 VLANs.

## Notes
Findings and Topology screens (Part 4) import review_network, draw_map and find_single_points from you. Do not rename them or change their return shapes. To add a rule, write one function and add it to RULES.

Branch name: `part3-...`; open a pull request when your piece works. The lead merges.
