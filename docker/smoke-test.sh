#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: smoke-test.sh IMAGE PLATFORM}"
PLATFORM="${2:?Usage: smoke-test.sh IMAGE PLATFORM}"
VOLUME="masterdnsvpn-smoke-${RANDOM}-${RANDOM}"
CONTAINER=""
TEST_DIR="$(mktemp -d)"
TEST_CREDENTIAL="0102030405060708.0000000000000000000000000000000000000000000000000000000000000000"

cleanup() {
  if [[ -n "${CONTAINER}" ]]; then
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  fi
  docker volume rm "${VOLUME}" >/dev/null 2>&1 || true
  rmdir "${TEST_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

wait_until_ready() {
  for ((attempt = 0; attempt < 60; attempt++)); do
    if [[ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER}")" != true ]]; then
      docker logs "${CONTAINER}"
      echo "Container exited before becoming ready on ${PLATFORM}." >&2
      return 1
    fi
    if docker logs "${CONTAINER}" 2>&1 | grep -q 'UDP Listener Ready'; then
      return 0
    fi
    sleep 1
  done
  docker logs "${CONTAINER}"
  echo "Container did not become ready on ${PLATFORM}." >&2
  return 1
}

stop_cleanly() {
  docker stop -t 10 "${CONTAINER}" >/dev/null
  if [[ "$(docker inspect --format '{{.State.ExitCode}}' "${CONTAINER}")" != 0 ]]; then
    docker logs "${CONTAINER}"
    echo "Container did not exit cleanly after SIGTERM on ${PLATFORM}." >&2
    return 1
  fi
}

docker volume create "${VOLUME}" >/dev/null
CONTAINER="$(docker run -d --platform "${PLATFORM}" --network none \
  -e DOMAIN=smoke.example.com -v "${VOLUME}:/data" "${IMAGE}" \
  -udp-host 127.0.0.1 -udp-port 15353 -device-credential "${TEST_CREDENTIAL}")"
wait_until_ready
stop_cleanly
docker rm "${CONTAINER}" >/dev/null
CONTAINER=""

# A fresh container must reuse /data without DOMAIN or access to GitHub.
CONTAINER="$(docker run -d --platform "${PLATFORM}" --network none \
  -v "${VOLUME}:/data" "${IMAGE}" -udp-host 127.0.0.1 -udp-port 15353 \
  -device-credential "${TEST_CREDENTIAL}")"
wait_until_ready
stop_cleanly
echo "${PLATFORM}: offline first boot, persisted config restart and SIGTERM passed."
