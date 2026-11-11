#!/bin/sh
# Remove every Docker object the integration tests created, including kept stacks.
# Only objects labelled website-ping.test=true are touched. The pinned Splunk,
# Python and Squid base images carry no such label and stay cached.
set -eu

LABEL="website-ping.test=true"

containers=$(docker ps -aq --filter "label=$LABEL")
if [ -n "$containers" ]; then
    # shellcheck disable=SC2086
    docker rm -f -v $containers
fi

volumes=$(docker volume ls -q --filter "label=$LABEL")
if [ -n "$volumes" ]; then
    # shellcheck disable=SC2086
    docker volume rm $volumes
fi

networks=$(docker network ls -q --filter "label=$LABEL")
if [ -n "$networks" ]; then
    # shellcheck disable=SC2086
    docker network rm $networks
fi

images=$(docker image ls -q --filter "label=$LABEL" | sort -u)
if [ -n "$images" ]; then
    # shellcheck disable=SC2086
    docker image rm $images
fi

for kind in "ps -a" "volume ls" "network ls" "image ls"; do
    # shellcheck disable=SC2086
    left=$(docker $kind -q --filter "label=$LABEL" | wc -l)
    if [ "$left" -ne 0 ]; then
        echo "test-clean: $left labelled object(s) left after: docker $kind" >&2
        exit 1
    fi
done
echo "test-clean: no labelled objects left"
