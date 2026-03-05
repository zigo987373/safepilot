#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=".env"
SECRETS_DIR="./secrets"
COMPOSE_OVERRIDE="./docker-compose.secrets.generated.yml"
GENERATE_MASTER_KEY=1

usage() {
  cat <<'USAGE'
Usage: scripts/sync-secrets-from-env.sh [options]

Translate known secret env vars from a .env file into file-based secrets.
Also generates a docker compose override that wires additional *_FILE vars + secrets.

Options:
  --env-file PATH           Source env file (default: .env)
  --secrets-dir PATH        Output secret directory (default: ./secrets)
  --compose-override PATH   Generated compose override file (default: ./docker-compose.secrets.generated.yml)
  --no-generate-master-key  Do not generate secrets/master_key when ORCH_MASTER_KEY is missing
  -h, --help                Show help

Notes:
  - The parser is safe-by-default: it does not execute .env content.
  - Supports KEY=VALUE, optional `export`, comments, single/double quoted values.
USAGE
}

trim_leading() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  printf '%s' "$s"
}

trim_trailing() {
  local s="$1"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

parse_env_value() {
  local raw="$1"
  raw="$(trim_leading "$raw")"

  if [[ "$raw" == \"* ]]; then
    if [[ "$raw" =~ ^\"(.*)\"[[:space:]]*$ ]]; then
      printf '%b' "${BASH_REMATCH[1]}"
      return 0
    fi
    return 1
  fi

  if [[ "$raw" == \'* ]]; then
    if [[ "$raw" =~ ^\'(.*)\'[[:space:]]*$ ]]; then
      printf '%s' "${BASH_REMATCH[1]}"
      return 0
    fi
    return 1
  fi

  raw="${raw%%[[:space:]]#*}"
  raw="$(trim_trailing "$raw")"
  printf '%s' "$raw"
}

set_parsed_var() {
  local key="$1"
  local value="$2"
  printf -v "__ENV_${key}" '%s' "$value"
}

get_parsed_var() {
  local key="$1"
  local ref="__ENV_${key}"
  printf '%s' "${!ref-}"
}

parse_env_file() {
  local line lineno key rhs value trimmed
  lineno=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    line="${line%$'\r'}"
    trimmed="$(trim_leading "$line")"

    [[ -z "$trimmed" ]] && continue
    [[ "$trimmed" == \#* ]] && continue

    if [[ "$trimmed" == export[[:space:]]* ]]; then
      trimmed="${trimmed#export}"
      trimmed="$(trim_leading "$trimmed")"
    fi

    if [[ ! "$trimmed" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      echo "warn: skipping unsupported line ${lineno} in ${ENV_FILE}" >&2
      continue
    fi

    key="${BASH_REMATCH[1]}"
    rhs="${BASH_REMATCH[2]}"

    if ! value="$(parse_env_value "$rhs")"; then
      echo "warn: skipping unparsable value for ${key} at line ${lineno}" >&2
      continue
    fi

    set_parsed_var "$key" "$value"
  done < "$ENV_FILE"
}

write_secret_file() {
  local filename="$1"
  local value="$2"
  local path="${SECRETS_DIR}/${filename}"
  umask 077
  printf '%s' "$value" > "$path"
  chmod 600 "$path"
}

generate_master_key_file() {
  local path="$1"

  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32 > "$path"
    chmod 600 "$path"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())' > "$path"
    chmod 600 "$path"
    return 0
  fi

  if command -v python >/dev/null 2>&1; then
    python -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())' > "$path"
    chmod 600 "$path"
    return 0
  fi

  echo "error: cannot generate master key automatically (missing openssl/python3/python)." >&2
  echo "error: set ORCH_MASTER_KEY in $ENV_FILE or pre-create ${path}" >&2
  return 1
}

# env_key|file_env_key|secret_file|is_base_compose_secret(1=yes)
MAPPINGS=$(cat <<'MAP'
BOT_TOKEN|BOT_TOKEN_FILE|bot_token|1
TELEGRAM_BOT_TOKEN|TELEGRAM_BOT_TOKEN_FILE|telegram_bot_token|0
OPENAI_API_KEY|OPENAI_API_KEY_FILE|openai_key|1
ANTHROPIC_API_KEY|ANTHROPIC_API_KEY_FILE|anthropic_key|0
ORCH_MASTER_KEY|ORCH_MASTER_KEY_FILE|master_key|1
BRAVE_API_KEY|BRAVE_API_KEY_FILE|brave_api_key|0
OPENWEATHER_API_KEY|OPENWEATHER_API_KEY_FILE|openweather_api_key|0
GITHUB_TOKEN|GITHUB_TOKEN_FILE|github_token|0
GITHUB_TOKEN_READ|GITHUB_TOKEN_READ_FILE|github_token_read|0
GITHUB_TOKEN_WRITE|GITHUB_TOKEN_WRITE_FILE|github_token_write|0
SLACK_BOT_TOKEN|SLACK_BOT_TOKEN_FILE|slack_bot_token|0
SLACK_BOT_TOKEN_READ|SLACK_BOT_TOKEN_READ_FILE|slack_bot_token_read|0
SLACK_BOT_TOKEN_WRITE|SLACK_BOT_TOKEN_WRITE_FILE|slack_bot_token_write|0
SLACK_BOT_API_TOKEN|SLACK_BOT_API_TOKEN_FILE|slack_bot_api_token|0
SLACK_BOT_API_TOKEN_READ|SLACK_BOT_API_TOKEN_READ_FILE|slack_bot_api_token_read|0
SLACK_BOT_API_TOKEN_WRITE|SLACK_BOT_API_TOKEN_WRITE_FILE|slack_bot_api_token_write|0
NOTION_API_KEY|NOTION_API_KEY_FILE|notion_api_key|0
NOTION_API_KEY_READ|NOTION_API_KEY_READ_FILE|notion_api_key_read|0
NOTION_API_KEY_WRITE|NOTION_API_KEY_WRITE_FILE|notion_api_key_write|0
NOTION_BOT_API_TOKEN|NOTION_BOT_API_TOKEN_FILE|notion_bot_api_token|0
NOTION_BOT_API_TOKEN_READ|NOTION_BOT_API_TOKEN_READ_FILE|notion_bot_api_token_read|0
NOTION_BOT_API_TOKEN_WRITE|NOTION_BOT_API_TOKEN_WRITE_FILE|notion_bot_api_token_write|0
LINEAR_API_KEY|LINEAR_API_KEY_FILE|linear_api_key|0
LINEAR_API_KEY_READ|LINEAR_API_KEY_READ_FILE|linear_api_key_read|0
LINEAR_API_KEY_WRITE|LINEAR_API_KEY_WRITE_FILE|linear_api_key_write|0
DISCORD_BOT_TOKEN|DISCORD_BOT_TOKEN_FILE|discord_bot_token|0
DISCORD_BOT_TOKEN_READ|DISCORD_BOT_TOKEN_READ_FILE|discord_bot_token_read|0
DISCORD_BOT_TOKEN_WRITE|DISCORD_BOT_TOKEN_WRITE_FILE|discord_bot_token_write|0
X_API_BEARER_TOKEN|X_API_BEARER_TOKEN_FILE|x_api_bearer_token|0
X_API_BEARER_TOKEN_READ|X_API_BEARER_TOKEN_READ_FILE|x_api_bearer_token_read|0
X_API_BEARER_TOKEN_WRITE|X_API_BEARER_TOKEN_WRITE_FILE|x_api_bearer_token_write|0
TODOIST_API_KEY|TODOIST_API_KEY_FILE|todoist_api_key|0
TODOIST_API_KEY_READ|TODOIST_API_KEY_READ_FILE|todoist_api_key_read|0
TODOIST_API_KEY_WRITE|TODOIST_API_KEY_WRITE_FILE|todoist_api_key_write|0
JIRA_API_TOKEN|JIRA_API_TOKEN_FILE|jira_api_token|0
JIRA_API_TOKEN_READ|JIRA_API_TOKEN_READ_FILE|jira_api_token_read|0
JIRA_API_TOKEN_WRITE|JIRA_API_TOKEN_WRITE_FILE|jira_api_token_write|0
MAP
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    --secrets-dir)
      SECRETS_DIR="$2"
      shift 2
      ;;
    --compose-override)
      COMPOSE_OVERRIDE="$2"
      shift 2
      ;;
    --no-generate-master-key)
      GENERATE_MASTER_KEY=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "error: env file not found: $ENV_FILE" >&2
  exit 1
fi

parse_env_file

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Required for current docker-compose.yml baseline.
bot_token_value="$(get_parsed_var BOT_TOKEN)"
if [[ -z "$bot_token_value" ]]; then
  bot_token_value="$(get_parsed_var TELEGRAM_BOT_TOKEN)"
fi
if [[ -z "$bot_token_value" ]]; then
  echo "error: missing BOT_TOKEN (or TELEGRAM_BOT_TOKEN) in $ENV_FILE" >&2
  exit 1
fi
write_secret_file "bot_token" "$bot_token_value"

openai_value="$(get_parsed_var OPENAI_API_KEY)"
if [[ -z "$openai_value" ]]; then
  echo "error: missing OPENAI_API_KEY in $ENV_FILE (required by current docker-compose.yml)" >&2
  exit 1
fi
write_secret_file "openai_key" "$openai_value"

master_key_value="$(get_parsed_var ORCH_MASTER_KEY)"
if [[ -n "$master_key_value" ]]; then
  write_secret_file "master_key" "$master_key_value"
elif [[ ! -f "${SECRETS_DIR}/master_key" ]]; then
  if [[ "$GENERATE_MASTER_KEY" -eq 1 ]]; then
    generate_master_key_file "${SECRETS_DIR}/master_key"
  else
    echo "error: missing ORCH_MASTER_KEY and ${SECRETS_DIR}/master_key not found" >&2
    exit 1
  fi
fi

extra_env_lines=()
extra_secret_defs=()
extra_secret_refs=()

while IFS='|' read -r env_key file_env_key secret_file is_base; do
  [[ -z "$env_key" ]] && continue

  value="$(get_parsed_var "$env_key")"
  [[ -z "$value" ]] && continue

  write_secret_file "$secret_file" "$value"

  if [[ "$is_base" == "0" ]]; then
    extra_env_lines+=("      ${file_env_key}: /run/secrets/${secret_file}")
    extra_secret_refs+=("      - ${secret_file}")
    extra_secret_defs+=("  ${secret_file}:")
    extra_secret_defs+=("    file: ${SECRETS_DIR}/${secret_file}")
  fi
done <<< "$MAPPINGS"

{
  echo "# Generated by scripts/sync-secrets-from-env.sh"
  echo "# Do not put secret values here; this file only references /run/secrets/*"
  echo "services:"
  echo "  safepilot:"

  if [[ ${#extra_env_lines[@]} -gt 0 ]]; then
    echo "    environment:"
    for line in "${extra_env_lines[@]}"; do
      echo "$line"
    done
  fi

  if [[ ${#extra_secret_refs[@]} -gt 0 ]]; then
    echo "    secrets:"
    for line in "${extra_secret_refs[@]}"; do
      echo "$line"
    done
  fi

  if [[ ${#extra_secret_defs[@]} -gt 0 ]]; then
    echo "secrets:"
    for line in "${extra_secret_defs[@]}"; do
      echo "$line"
    done
  fi
} > "$COMPOSE_OVERRIDE"

chmod 600 "$COMPOSE_OVERRIDE"

echo "Wrote secrets to: $SECRETS_DIR"
echo "Wrote compose override: $COMPOSE_OVERRIDE"
echo "Next: docker compose -f docker-compose.yml -f $COMPOSE_OVERRIDE up -d"
