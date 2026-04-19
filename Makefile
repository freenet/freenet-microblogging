# Works with GNU Make 3.81+ (no .ONESHELL dependency)

PROJECT_DIR := $(abspath .)
WEB_DIR := $(PROJECT_DIR)/web
POSTS_DIR := $(PROJECT_DIR)/contracts/posts
FOLLOWS_DIR := $(PROJECT_DIR)/contracts/follows
LIKES_DIR := $(PROJECT_DIR)/contracts/likes
IDENTITY_DIR := $(PROJECT_DIR)/delegates/identity

ifeq ($(CARGO_TARGET_DIR),)
$(error CARGO_TARGET_DIR is not set)
endif

build: \
	posts \
	follows \
	likes \
	identity \
	publish-posts \
	publish-follows \
	publish-likes \
	publish-identity \
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
	cargo test -p freenet-microblogging-likes
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

likes:
	cd $(LIKES_DIR) && fdev build

publish-likes:
	fdev publish --code $(CARGO_TARGET_DIR)/wasm32-unknown-unknown/release/freenet_microblogging_likes.wasm contract --state $(LIKES_DIR)/initial_state.json

publish-follows:
	fdev publish --code $(CARGO_TARGET_DIR)/wasm32-unknown-unknown/release/freenet_microblogging_follows.wasm contract --state $(FOLLOWS_DIR)/initial_state.json

identity:
	cd $(IDENTITY_DIR) && fdev build --package-type delegate

publish-identity:
	fdev publish --code $(IDENTITY_DIR)/build/freenet/freenet_microblogging_identity delegate 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -o 'key: [^ ,]*' | head -1 | cut -d' ' -f2 | tr -d '\n' > $(WEB_DIR)/delegate_key.txt
	@echo "Delegate key: $$(cat $(WEB_DIR)/delegate_key.txt)"
	@echo "Computing delegate key bytes and code_hash from WASM..."
	@WASM=$(PROJECT_DIR)/target/wasm32-unknown-unknown/release/freenet_microblogging_identity.wasm && \
		code_hash_hex=$$(b3sum --no-names "$$WASM" | tr -d '[:space:]') && \
		key_hex=$$(echo -n "$$code_hash_hex" | xxd -r -p | b3sum --no-names | tr -d '[:space:]') && \
		node -e "const h=process.argv[1];console.log(JSON.stringify(Array.from(Buffer.from(h,'hex'))))" "$$key_hex" > $(WEB_DIR)/delegate_key_bytes.json && \
		node -e "const h=process.argv[1];console.log(JSON.stringify(Array.from(Buffer.from(h,'hex'))))" "$$code_hash_hex" > $(WEB_DIR)/delegate_code_hash_bytes.json && \
		echo "key_bytes and code_hash_bytes written (32 bytes each)"

clean-node:
	rm -rf ~/Library/Application\ Support/The-Freenet-Project-Inc.Freenet
	rm -rf ~/Library/Caches/The-Freenet-Project-Inc.freenet

clean:
	cargo clean
	rm -rf $(WEB_DIR)/dist $(WEB_DIR)/build
	rm -f $(WEB_DIR)/model_code_hash.txt $(WEB_DIR)/delegate_key.txt $(WEB_DIR)/delegate_key_bytes.json $(WEB_DIR)/delegate_code_hash_bytes.json

run-node:
	RUST_BACKTRACE=1 RUST_LOG=freenet=debug,locutus_core=debug,locutus_node=debug,info freenet local --ws-api-address 127.0.0.1
