# Works with GNU Make 3.81+ (no .ONESHELL dependency)

PROJECT_DIR := $(abspath .)
WEB_DIR := $(PROJECT_DIR)/web
POSTS_DIR := $(PROJECT_DIR)/contracts/posts
FOLLOWS_DIR := $(PROJECT_DIR)/contracts/follows
IDENTITY_DIR := $(PROJECT_DIR)/delegates/identity

ifeq ($(CARGO_TARGET_DIR),)
$(error CARGO_TARGET_DIR is not set)
endif

build: \
	posts \
	follows \
	publish-posts \
	publish-follows \
	webapp \
	publish-webapp

node: \
	build-tool \
	run-node

build-tool:
	cargo install freenet
	cargo install fdev

test:
	cargo test -p freenet-microblogging-posts
	cargo test -p freenet-microblogging-follows
	cd $(WEB_DIR) && npm test

check:
	cargo check
	cd $(WEB_DIR) && npx tsc --noEmit

webapp:
	cd $(WEB_DIR) && npm install && npm run build && fdev build

publish-webapp:
	fdev publish --code $(CARGO_TARGET_DIR)/wasm32-unknown-unknown/release/freenet_microblogging_web.wasm contract --state $(WEB_DIR)/build/freenet/contract-state

posts:
	cd $(POSTS_DIR) && fdev build
	hash=$$(fdev inspect $(POSTS_DIR)/build/freenet/freenet_microblogging_posts key | grep 'code key:' | cut -d' ' -f3) && \
		echo $$hash && \
		printf '%s' $$hash > $(WEB_DIR)/model_code_hash.txt

publish-posts:
	fdev publish --code $(CARGO_TARGET_DIR)/wasm32-unknown-unknown/release/freenet_microblogging_posts.wasm contract --state $(POSTS_DIR)/initial_state.json

follows:
	cd $(FOLLOWS_DIR) && fdev build

publish-follows:
	fdev publish --code $(CARGO_TARGET_DIR)/wasm32-unknown-unknown/release/freenet_microblogging_follows.wasm contract --state $(FOLLOWS_DIR)/initial_state.json

identity:
	cd $(IDENTITY_DIR) && fdev build --package-type delegate

run-node:
	RUST_BACKTRACE=1 RUST_LOG=freenet=debug,locutus_core=debug,locutus_node=debug,info freenet local --ws-api-address 127.0.0.1
