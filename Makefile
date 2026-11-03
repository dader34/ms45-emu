# ms45-emu: the sets that matter, each one command.
#
#   make test     the emulator's own pytest suite (tests/)
#   make proofs   every proof in tools/proofs, in order; stops at the first FAIL
#   make export   regenerate what BMWeb carries from here (tools/export), the
#                 quick ones: the flasher, bootloader and live tune blobs and
#                 the Comfort "Always live" group
#   make maps     the two slow exporters (minutes of emulator time): the live
#                 cursor's axis map and the measurement value map
#
# PY points at the interpreter; BMWEB at the app checkout (default: beside).

PY    ?= .venv/bin/python
BMWEB ?= ../inpa-mac-bridge
GEN   := $(BMWEB)/app/renderer/core/generated

PROOFS := gate_test flasher_session_test mpc_session_test nrv2b_emu_test \
          bl_test bl_app_test bl_restore_test bl_update_test bl_late_entry_test \
          bootwrite_test flash_resume_test aif_editor_test livetune_app_test

.PHONY: test proofs export maps

test:
	$(PY) -m pytest -q

proofs:
	@for p in $(PROOFS); do \
	  echo "== $$p"; $(PY) -m tools.proofs.$$p || exit 1; \
	done

export:
	$(PY) -m tools.export.fast_flasher_js
	$(PY) -m tools.export.bl_js
	$(PY) -m tools.export.livetune_js
	$(PY) -m tools.export.comfort_live --js $(GEN)/comfort-live.js

maps:
	$(PY) -m tools.export.livetune_cursor --js $(GEN)/ms45-cursor-map.js
	$(PY) -m tools.export.values_map --js $(GEN)/ms45-value-map.js \
	  --tables $(BMWEB)/app/renderer/data/ecu-src/ms450ds0.tables.json.gz
