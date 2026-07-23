#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-status}"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTAINER="${NEXUS_AI_CONTAINER:-nexus-ai-local}"
API_KEY="${NEXUS_AI_API_KEY:-nexus-local}"
PORT="${NEXUS_AI_PORT:-8080}"
CACHE="${NEXUS_AI_CACHE:-$HOME/.cache/nexus-ai}"
PYTHON="$PROJECT_DIR/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON=python3

mapfile -t AUTO_PROFILE < <(
    PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" -c \
        'from osint_toolkit.ai.performance import main; main()' \
        --profile "${NEXUS_AI_PROFILE:-auto}" --values
)
PROFILE="${AUTO_PROFILE[0]}"
MODEL="${NEXUS_AI_GGUF:-${AUTO_PROFILE[1]}}"
CONTEXT="${NEXUS_AI_CONTEXT:-${AUTO_PROFILE[2]}}"
MAX_TOKENS="${NEXUS_AI_MAX_TOKENS:-${AUTO_PROFILE[3]}}"
THREADS="${NEXUS_AI_THREADS:-${AUTO_PROFILE[4]}}"
GPU_LAYERS="${NEXUS_AI_GPU_LAYERS:-${AUTO_PROFILE[5]}}"
GPU_NAME="${AUTO_PROFILE[6]}"
VRAM="${AUTO_PROFILE[7]}"

command -v docker >/dev/null 2>&1 || {
    if [[ "$ACTION" == "profile" ]]; then
        PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
            "$PYTHON" -c \
            'from osint_toolkit.ai.performance import main; main()' \
            --profile "${NEXUS_AI_PROFILE:-auto}"
        exit 0
    fi
    printf 'Docker is required for the local model launcher.\n' >&2
    exit 1
}

DOCKER_GPU=false
if ((GPU_LAYERS > 0)); then
    if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -qi nvidia \
        || [[ -s /etc/cdi/nvidia.yaml || -s /var/run/cdi/nvidia.yaml ]]; then
        DOCKER_GPU=true
    elif [[ -z "${NEXUS_AI_PROFILE:-}" || "${NEXUS_AI_PROFILE:-}" == "auto" ]]; then
        printf 'GPU NVIDIA detected, but unavailable in Docker; using compact CPU fallback.\n' >&2
        mapfile -t AUTO_PROFILE < <(
            PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
                "$PYTHON" -c \
                'from osint_toolkit.ai.performance import main; main()' \
                --profile compact --values
        )
        PROFILE="${AUTO_PROFILE[0]}"
        MODEL="${NEXUS_AI_GGUF:-${AUTO_PROFILE[1]}}"
        CONTEXT="${NEXUS_AI_CONTEXT:-${AUTO_PROFILE[2]}}"
        MAX_TOKENS="${NEXUS_AI_MAX_TOKENS:-${AUTO_PROFILE[3]}}"
        THREADS="${NEXUS_AI_THREADS:-${AUTO_PROFILE[4]}}"
        GPU_LAYERS=0
    fi
fi

if ((GPU_LAYERS > 0)); then
    IMAGE="${NEXUS_AI_IMAGE:-ghcr.io/ggml-org/llama.cpp:server-cuda}"
    GPU_ARGS=(--gpus all)
else
    IMAGE="${NEXUS_AI_IMAGE:-ghcr.io/ggml-org/llama.cpp:server}"
    GPU_ARGS=()
fi

MODEL_REPO="${MODEL%%:*}"
MODEL_QUANT="${MODEL#*:}"
MODEL_BASENAME="${MODEL_REPO##*/}"
MODEL_BASENAME="${MODEL_BASENAME%-GGUF}"
MODEL_FILENAME="${MODEL_BASENAME}-${MODEL_QUANT}.gguf"
MODEL_PATH="$CACHE/$MODEL_FILENAME"
MODEL_URL="https://huggingface.co/$MODEL_REPO/resolve/main/$MODEL_FILENAME"

case "$ACTION" in
    start)
        if [[ "$PROFILE" == "core" || -z "$MODEL" ]]; then
            printf 'Nexus AI selected Core mode: no model server is required.\n'
            printf 'Set NEXUS_AI_PROFILE=lite|compact|balanced|performance to override.\n'
            exit 0
        fi
        mkdir -p "$CACHE"
        if [[ ! -s "$MODEL_PATH" ]]; then
            command -v curl >/dev/null 2>&1 || {
                printf 'curl is required to download the selected GGUF model.\n' >&2
                exit 1
            }
            printf 'Downloading %s to the persistent Nexus AI cache…\n' "$MODEL_FILENAME"
            curl --location --fail --retry 3 --continue-at - \
                --output "$MODEL_PATH" "$MODEL_URL"
        fi
        if docker inspect "$CONTAINER" >/dev/null 2>&1; then
            EXISTING_PROFILE="$(
                docker inspect --format \
                    '{{ index .Config.Labels "org.nexus.ai.profile" }}' \
                    "$CONTAINER"
            )"
            EXISTING_MODEL="$(
                docker inspect --format \
                    '{{ index .Config.Labels "org.nexus.ai.model" }}' \
                    "$CONTAINER"
            )"
            if [[ "$EXISTING_PROFILE" != "$PROFILE" || "$EXISTING_MODEL" != "$MODEL" ]]; then
                printf 'Hardware profile changed; replacing the previous AI container.\n'
                docker rm --force "$CONTAINER" >/dev/null
            else
                docker start "$CONTAINER" >/dev/null
            fi
        fi
        if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
            docker run --detach \
                --name "$CONTAINER" \
                --label "org.nexus.ai.profile=$PROFILE" \
                --label "org.nexus.ai.model=$MODEL" \
                --label "org.nexus.ai.acceleration=$([[ ${#GPU_ARGS[@]} -gt 0 ]] && printf gpu || printf cpu)" \
                "${GPU_ARGS[@]}" \
                --publish "127.0.0.1:$PORT:8080" \
                --volume "$CACHE:/models:ro" \
                "$IMAGE" \
                --model "/models/$MODEL_FILENAME" \
                --alias local \
                --api-key "$API_KEY" \
                --host 0.0.0.0 \
                --port 8080 \
                --ctx-size "$CONTEXT" \
                --threads "$THREADS" \
                --n-gpu-layers "$GPU_LAYERS" \
                --n-predict "$MAX_TOKENS"
        fi
        printf 'Adaptive profile: %s · model: %s\n' "$PROFILE" "$MODEL"
        if ((${#GPU_ARGS[@]})); then
            printf 'Acceleration: GPU · %s · %s GiB VRAM\n' "$GPU_NAME" "$VRAM"
        else
            printf 'Acceleration: CPU (NVIDIA Container Toolkit indisponible)\n'
        fi
        printf 'Nexus local AI is starting on http://127.0.0.1:%s/v1\n' "$PORT"
        printf 'First start downloads the selected quantized model. Follow with:\n'
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
    profile)
        PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
            "$PYTHON" -c \
            'from osint_toolkit.ai.performance import main; main()' \
            --profile "${NEXUS_AI_PROFILE:-auto}"
        ;;
    monitor)
        PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
            "$PYTHON" -c \
            'from osint_toolkit.ai.performance import main; main()' \
            --watch
        ;;
    logs)
        docker logs --follow "$CONTAINER"
        ;;
    stop)
        docker stop "$CONTAINER" >/dev/null
        printf 'Nexus local AI stopped; model cache was preserved.\n'
        ;;
    *)
        printf 'Usage: %s {start|status|profile|monitor|logs|stop}\n' "$0" >&2
        exit 2
        ;;
esac
