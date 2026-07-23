#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-status}"
CONTAINER="${NEXUS_AI_CONTAINER:-nexus-ai-local}"
IMAGE="${NEXUS_AI_IMAGE:-ghcr.io/ggml-org/llama.cpp:server}"
MODEL="${NEXUS_AI_GGUF:-Qwen/Qwen3-4B-GGUF:Q4_K_M}"
API_KEY="${NEXUS_AI_API_KEY:-nexus-local}"
PORT="${NEXUS_AI_PORT:-8080}"
CACHE="${NEXUS_AI_CACHE:-$HOME/.cache/huggingface}"

command -v docker >/dev/null 2>&1 || {
    printf 'Docker is required for this launcher.\n' >&2
    exit 1
}

case "$ACTION" in
    start)
        mkdir -p "$CACHE"
        if docker inspect "$CONTAINER" >/dev/null 2>&1; then
            docker start "$CONTAINER" >/dev/null
        else
            docker run --detach \
                --name "$CONTAINER" \
                --publish "127.0.0.1:$PORT:8080" \
                --volume "$CACHE:/root/.cache/huggingface" \
                "$IMAGE" \
                --hf-repo "$MODEL" \
                --alias local \
                --api-key "$API_KEY" \
                --host 0.0.0.0 \
                --port 8080 \
                --ctx-size 4096 \
                --n-predict 900
        fi
        printf 'Nexus local AI is starting on http://127.0.0.1:%s/v1\n' "$PORT"
        printf 'First start downloads the quantized model. Follow with:\n'
        printf '  docker logs -f %s\n' "$CONTAINER"
        ;;
    status)
        if curl --silent --fail \
            --header "Authorization: Bearer $API_KEY" \
            "http://127.0.0.1:$PORT/health" >/dev/null; then
            printf 'Nexus local AI is ready on port %s.\n' "$PORT"
        elif docker inspect "$CONTAINER" >/dev/null 2>&1; then
            printf 'Container exists but the model is still loading or stopped.\n'
            docker ps --all --filter "name=^/${CONTAINER}$" --format '{{.Status}}'
            exit 2
        else
            printf 'Nexus local AI is not started.\n'
            exit 3
        fi
        ;;
    logs)
        docker logs --follow "$CONTAINER"
        ;;
    stop)
        docker stop "$CONTAINER" >/dev/null
        printf 'Nexus local AI stopped; model cache was preserved.\n'
        ;;
    *)
        printf 'Usage: %s {start|status|logs|stop}\n' "$0" >&2
        exit 2
        ;;
esac
