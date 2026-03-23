CORES := $(shell nproc)
ROOT_DIR := $(shell git rev-parse --show-toplevel)
install:
	foundryup
	cd $(ROOT_DIR) && git submodule update --init --recursive --remote
	if [ -d lib/ETHDILITHIUM/pythonref ]; then cd lib/ETHDILITHIUM/pythonref && make install; fi
	if [ -d lib/ETHFALCON/pythonref ]; then cd lib/ETHFALCON/pythonref && make install; fi
test_opt:
	forge test -j$(CORES) -vv
test_not_opt:
	FOUNDRY_PROFILE=lite forge test -j$(CORES) -vv
