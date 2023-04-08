# Copyright © 2023 Exact Realty Limited
#
# All rights reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

TARGET_DIR := $(or $(TARGET_DIR),dist)

NODE_ENV := $(or $(NODE_ENV))

DOCKER ?= docker
NPM ?= npm

dir_guard=@mkdir -p $(@D)

all: deps

clean:
	$(RM) -r dist

deps: $(TARGET_DIR)/.deps
$(TARGET_DIR)/.deps: export NODE_ENV = test
$(TARGET_DIR)/.deps: package.json package-lock.json
	$(dir_guard)
	$(NPM) $(if $(strip $(CI)),ci,install)
	$(NPM) run lint
	$(NPM) run test
	touch $@

build: $(TARGET_DIR)/.build
$(TARGET_DIR)/.build: export NODE_ENV := $(NODE_ENV)
$(TARGET_DIR)/.build: export BUILD_TARGET_DIR = $(TARGET_DIR)
$(TARGET_DIR)/.build: deps esbuild.mjs
	$(dir_guard)
	$(NPM) run build
	touch $@

.PHONY: all clean deps build
