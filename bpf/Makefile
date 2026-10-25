# Style checks for the BPF code, the way Cilium does them
# (cilium/bpf/Makefile.bpf): the kernel's checkpatch.pl, run from Cilium's
# pinned cilium-checkpatch image with its options and ignore list.
#
#   make -C bpf checkpatch                        # each commit since the parent branch, then uncommitted changes
#   make -C bpf checkpatch CHECKPATCH_OPTS=-a     # every file in bpf/
#   make -C bpf checkpatch CHECKPATCH_OPTS=-a CHECKPATCH_ARGS=--fix-inplace
#
# On a GitHub pull request (GITHUB_REF=refs/pull/N/merge) it checks each
# commit of the PR instead, listed through the GitHub API.

CONTAINER_ENGINE ?= docker

CHECKPATCH_IMAGE := quay.io/cilium/cilium-checkpatch:1755701578-b97bd7a@sha256:f1332fa6edbbd40882a59ceae4a7843a4095bd62288363740e84b82708624c50

# Options of the image's checkpatch.sh: -a (all files instead of commits),
# -i (without --strict), -q (quiet).
CHECKPATCH_OPTS ?=
# Options for checkpatch.pl itself. MACRO_ARG_REUSE is ignored, as in Cilium.
CHECKPATCH_ARGS ?=

checkpatch:
	$(CONTAINER_ENGINE) container run --rm \
		--workdir /workspace \
		--volume $(CURDIR)/..:/workspace \
		--user "$(shell id -u):$(shell id -g)" \
		-e GITHUB_REF=$(GITHUB_REF) -e GITHUB_REPOSITORY=$(GITHUB_REPOSITORY) -e GITHUB_TOKEN=$(GITHUB_TOKEN) \
		--entrypoint /bin/bash $(CHECKPATCH_IMAGE) /checkpatch/checkpatch.sh \
		$(CHECKPATCH_OPTS) -- --ignore MACRO_ARG_REUSE $(CHECKPATCH_ARGS)

.PHONY: checkpatch
