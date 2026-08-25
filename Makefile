# browserid-bsky — standard targets (same vocabulary in browserid-ng, mingo, sbo):
#
#   make build            compile the workspace
#   make test             run the test suite
#   make push             push HEAD to origin (triggers the CI image build)
#   make watch            watch CI runs for HEAD until they all finish
#   make release          release HEAD's bridge image to dokku
#   make deploy           push + watch (CI releases the images itself)
#
# Deploy model: CI builds the pds-bridge image (.github/workflows/
# deploy-bridge.yml → ghcr.io/vthunder/browserid-bsky/pds-bridge) and releases
# it itself (browserid-bsky-ci dokku key + DOKKU_HOST=browserid.me, fixed
# 2026-08-11). `release` is the manual fallback via the mini-ops key. The
# `bsky-pds` app is the upstream PDS image, managed directly in dokku — not
# deployed from this repo.

SHA  := $(shell git rev-parse HEAD)
HOST ?= dokku@browserid.me
SSH  := ssh -i $(HOME)/.ssh/mini-ops -o StrictHostKeyChecking=accept-new
REG  := ghcr.io/vthunder/browserid-bsky

.PHONY: build test push watch release release-bridge deploy

build:
	cargo build --workspace

test:
	cargo test --workspace

push:
	git push origin HEAD

# gh's --commit filter needs the FULL sha — a short sha silently matches nothing.
watch:
	@echo "Watching CI for $(SHA)…"
	@# Runs take a few seconds to register after a push — wait for them to
	@# APPEAR before waiting for them to finish, or this exits instantly.
	@until gh run list --commit $(SHA) --json status -q '.[].status' | grep -q .; do sleep 5; done
	@while gh run list --commit $(SHA) --json status -q '.[].status' \
	    | grep -qE 'in_progress|queued|requested|waiting'; do sleep 15; done
	@gh run list --commit $(SHA)

# `git:from-image` exits 1 on an unchanged digest — tolerated.
release-bridge: ; -$(SSH) $(HOST) git:from-image bsky-bridge $(REG)/pds-bridge:$(SHA)
release: release-bridge

deploy: push watch
