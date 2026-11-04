#!/bin/bash
set -ueo pipefail

[ -z "${TMPDIR:-}" ] && TMPDIR=${TMPDIR:-/tmp}

# Holds the server and the token a jwt login minted, for pre-exit to revoke.
plugin_token_file() {
  echo "${TMPDIR}/vault-secrets-plugin-${BUILDKITE_JOB_ID:-local}.token"
}

assume_role_via_cert_auth() {
  local vault_sts_role="$1"
  local cert_path="$2"
  local cert_key_path="$3"
  local server="${4:-$VAULT_ADDR}"
  local cert_mount="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_MOUNT:-machine-auth-g1}"

  if [[ ! -f "$cert_path" ]]; then
    echo "+++ cert-path not found: $cert_path" >&2
    exit 1
  fi
  if [[ ! -f "$cert_key_path" ]]; then
    echo "+++ cert-key-path not found: $cert_key_path" >&2
    exit 1
  fi

  echo "Authenticating to Vault via cert auth (mount: $cert_mount)" >&2
  local cert_token
  local cert_err_file
  cert_err_file=$(mktemp "${TMPDIR}/vault-cert-err.XXXXXX")
  if ! cert_token=$(vault login -field=token -address="$server" \
      -method=cert \
      -client-cert="$cert_path" \
      -client-key="$cert_key_path" \
      name="$cert_mount" 2>"$cert_err_file"); then
    echo "+++ Cert auth failed" >&2
    cat "$cert_err_file" >&2 || true
    rm -f "$cert_err_file"
    exit 1
  fi
  rm -f "$cert_err_file"

  echo "Reading AWS credentials from Vault AWS secrets engine (role: $vault_sts_role)" >&2
  local aws_creds
  local sts_err_file
  sts_err_file=$(mktemp "${TMPDIR}/vault-sts-err.XXXXXX")
  if ! aws_creds=$(VAULT_TOKEN="$cert_token" vault read -address="$server" \
      -format=json "aws/sts/$vault_sts_role" 2>"$sts_err_file"); then
    echo "+++ Failed to get AWS credentials via Vault AWS engine" >&2
    cat "$sts_err_file" >&2 || true
    rm -f "$sts_err_file"
    exit 1
  fi
  rm -f "$sts_err_file"

  echo "$aws_creds"
}

vault_auth() {
  local server="$1"

  # The plugin currently supports AppRole and AWS authentication
  # These values are referenced when authenticating to the Vault server:
  #   BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD - 'approle' or 'aws'

  ##  AppRole Authentication
  #   SecretID should be stored securely on the agent when using AppRole authentication.
  #   The plugin will reference these two values for the RoleID and SecretID:
  #     BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_SECRET_ENV (default: $VAULT_SECRET_ID)
  #     BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID

  ##  AWS Authentication
  #   AWS auth method only requires you to pass the name of a valid Vault role in your login call, which is not
  #   sensitive information itself, so the role name to use can either be passed via BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME
  #   or will fall back to using the name of the IAM role that the instance is using.


  case "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD:-}" in

    approle)
        if [ -z "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_SECRET_ENV:-}" ]; then
          secret_var="${VAULT_SECRET_ID?No Secret ID found}"
        else
          secret_var="${!BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_SECRET_ENV}"
        fi

        if [[ -z "${secret_var:-}" ]]; then
          echo "+++ No vault secret id found" >&2
          exit 1
        fi

        local auth_mount="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT:-}"
        local approle_path="auth/approle/login"
        if [[ -n "$auth_mount" ]]; then
          approle_path="auth/${auth_mount}/login"
        fi

        local approle_rc=0
        VAULT_TOKEN=$(vault write -field=token -address="$server" "$approle_path" \
          role_id="$BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID" \
          secret_id="${secret_var:-}") || approle_rc=$?

        if [[ $approle_rc -ne 0 ]]; then
          echo "+++ Failed to get vault token" >&2
          exit $approle_rc
        fi

        export VAULT_TOKEN
        track_redacted_env "VAULT_TOKEN"

        echo "Successfully authenticated with RoleID ${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID} and updated vault token"
      ;;

    aws)
        local cert_path="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH:-}"
        local cert_key_path="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH:-}"
        local cred_prefix="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_CREDENTIAL_NAME_PREFIX:-}"
        local aws_vault_role="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE:-}"

        if [ -z "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME:-}" ]; then
          EC2_INSTANCE_IAM_ROLE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials)
          aws_role_name="${EC2_INSTANCE_IAM_ROLE}"
        else
          aws_role_name="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME}"
        fi

        if [[ -z "${aws_role_name:-}" ]]; then
          echo "+++ No Vault role name defined and no EC2 instance IAM role found" >&2
          exit 1
        fi

        local -a vault_login_args=(-field=token "-address=$server" -method=aws "role=$aws_role_name")
        local aws_auth_header="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_HEADER_VALUE:-}"
        local auth_mount="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT:-}"

        if [[ -n "$aws_auth_header" ]]; then
          vault_login_args+=("header_value=$aws_auth_header")
        fi
        if [[ -n "$auth_mount" ]]; then
          vault_login_args+=("mount=$auth_mount")
        fi

        if [[ -n "$cert_path" || -n "$cert_key_path" ]]; then
          if [[ -z "$cert_path" || -z "$cert_key_path" ]]; then
            echo "+++ cert-path and cert-key-path must both be set" >&2
            exit 1
          fi
          if [[ -z "$aws_vault_role" ]]; then
            echo "+++ aws-vault-sts-role is required when using cert-path/cert-key-path" >&2
            exit 1
          fi
          echo "On-prem detected: using cert-based bootstrap" >&2
          local sts_output
          sts_output=$(assume_role_via_cert_auth "$aws_vault_role" "$cert_path" "$cert_key_path" "$server")
          local assumed_ak assumed_sk assumed_st
          assumed_ak=$(echo "$sts_output" | jq -r '.data.access_key // empty')
          assumed_sk=$(echo "$sts_output" | jq -r '.data.secret_key // empty')
          assumed_st=$(echo "$sts_output" | jq -r '.data.security_token // empty')
          if [[ -z "$assumed_ak" || -z "$assumed_sk" || -z "$assumed_st" ]]; then
            echo "+++ Failed to extract credentials from Vault AWS engine response" >&2
            exit 1
          fi
          vault_login_args+=("aws_access_key_id=$assumed_ak")
          vault_login_args+=("aws_secret_access_key=$assumed_sk")
          vault_login_args+=("aws_security_token=$assumed_st")
        elif [[ -n "$cred_prefix" ]]; then
          local ak_var="${cred_prefix}AWS_ACCESS_KEY_ID"
          local sk_var="${cred_prefix}AWS_SECRET_ACCESS_KEY"
          local st_var="${cred_prefix}AWS_SESSION_TOKEN"
          if [[ -z "${!ak_var:-}" || -z "${!sk_var:-}" || -z "${!st_var:-}" ]]; then
            echo "+++ AWS credentials not found with prefix '${cred_prefix}'" >&2
            echo "    Expected: ${ak_var}, ${sk_var}, ${st_var}" >&2
            echo "    Ensure the aws-assume-role-with-web-identity plugin runs before this plugin" >&2
            exit 1
          fi
          vault_login_args+=("aws_access_key_id=${!ak_var}")
          vault_login_args+=("aws_secret_access_key=${!sk_var}")
          vault_login_args+=("aws_security_token=${!st_var}")
          echo "Using AWS credentials from ${cred_prefix}AWS_* env vars" >&2
        fi

        local vault_login_rc=0
        VAULT_TOKEN=$(vault login "${vault_login_args[@]}") || vault_login_rc=$?

        if [[ $vault_login_rc -ne 0 ]]; then
          echo "+++ Failed to get vault token" >&2
          exit $vault_login_rc
        fi

        export VAULT_TOKEN
        track_redacted_env "VAULT_TOKEN"

        echo "Successfully authenticated with IAM Role ${aws_role_name} and updated vault token"
      ;;

    jwt)
        echo "--- performing JWT authentication"
        if [ -n "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV:-}" ]; then
          jwt_var="${!BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV}"
        elif [ -n "${VAULT_JWT:-}" ]; then
          jwt_var="${VAULT_JWT}"
        else
          echo "Requesting a Buildkite OIDC token for audience ${server}" >&2
          if ! jwt_var=$(buildkite-agent oidc request-token --audience "$server" --lifetime 300); then
            echo "+++ Failed to request a Buildkite OIDC token" >&2
            exit 1
          fi
        fi

        if [[ -z "${jwt_var:-}" ]]; then
          echo "+++ No JWT found." >&2
          exit 1
        fi

        local auth_mount="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT:-}"
        local jwt_path="auth/jwt/login"
        if [[ -n "$auth_mount" ]]; then
          jwt_path="auth/${auth_mount}/login"
        fi

        local jwt_rc=0
        VAULT_TOKEN=$(vault write -field=token -address="$server" "$jwt_path" \
          role="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ROLE:-"buildkite"}" \
          jwt="${jwt_var:-}") || jwt_rc=$?

        if [[ $jwt_rc -ne 0 ]]; then
          echo "+++ Failed to get vault token" >&2
          exit $jwt_rc
        fi

        export VAULT_TOKEN
        track_redacted_env "VAULT_TOKEN"
        # A file, not env: the agent drops this hook's exports when the hook fails.
        (umask 077 && printf '%s\n%s\n' "$server" "$VAULT_TOKEN" >"$(plugin_token_file)")

        echo "Successfully authenticated with JWT"
    ;;
  esac
}

list_secrets() {
  local server="$1"
  local key="$2"

  local _list
  local list_rc=0

  _list=$(vault kv list -address="$server" -format=yaml "$key" 2>&1 | sed 's/^- //g') || list_rc=$?

  if [[ $list_rc -ne 0 ]]; then
    echo "unable to list secrets at $key: $_list" >&2
    return $list_rc
  fi

  for lineItem in ${_list}; do
    echo "$key/${lineItem}"
  done

  return 0
}

secret_exists() {
  local server="$1"
  local key="$2"

  local _key_base
  _key_base="$(dirname "$key")"
  local _key_name
  _key_name="$(basename "$key")"
  local _list
  _list=$(vault kv list -address="$server" -format=yaml "$_key_base")

  echo "${_list}" | grep "^- ${_key_name}$" >&/dev/null
  # shellcheck disable=SC2181
  if [ "$?" -ne 0 ]; then
    return 1
  else
    return 0
  fi
}

process_json_to_shell_vars() {
  local json_input="$1"

  # Process JSON secret to replace non-alphanumeric characters in keys with underscores,
  # flatten nested structures by joining paths with underscores, and format as shell variables
  jq -c '
      walk(
          if type == "object" then
              with_entries(.key |= gsub("[^A-Za-z0-9_]"; "_"))
          else
              .
          end
      )
  ' <<< "$json_input" | jq -r '
      [paths(scalars) as $p |
          {key: $p | join("_"), value: getpath($p)}
      ] | .[] | "\(.key)=\(.value | @sh)"
  '
}

secret_download() {
  local server="$1"
  local key="$2"
  # should default to YAML, but allows the option for getting JSON output.
  local output="${BUILDKITE_PLUGIN_VAULT_SECRETS_OUTPUT:-"yaml"}"

  # Attempt to retrieve the secret from Vault with detailed error capture.
  # IMPORTANT: `vault kv get` writes the secret to stdout. Never echo captured
  # stdout in an error path - only Vault's stderr is safe to surface, otherwise
  # secret material (e.g. partially streamed before a mid-transfer EOF/5xx) would
  # leak into the build log.
  local vault_error
  local _vault_stderr
  _vault_stderr=$(mktemp)
  # secret_download is always invoked inside a command substitution subshell, so
  # an EXIT trap reliably cleans up the temp file on every path (success, the
  # several `exit 1` error paths, or an interrupt) without scattering `rm -f`.
  # Intentional early expansion: capture the literal path now before the local variable
  # goes out of scope when the function returns.
  # shellcheck disable=SC2064
  trap "rm -f $_vault_stderr" EXIT

  if [[ "${output}" == "json" ]]; then
    # JSON output - no sed transformation needed
    if ! _secret=$(vault kv get -address="$server" -field=data -format=json "$key" 2>"$_vault_stderr"); then
      vault_error=$(cat "$_vault_stderr")
      echo "Failed to download secret from $key" >&2
      echo "Vault error: $vault_error" >&2

      if [[ "$vault_error" =~ "EOF" ]]; then
        echo "EOF error often indicates network connectivity issues or server problems" >&2
      elif [[ "$vault_error" =~ "permission denied" ]]; then
        echo "Permission denied - check if the token has access to this secret path" >&2
      elif [[ "$vault_error" =~ "path not found" ]]; then
        echo "Secret path not found - verify the path exists in Vault" >&2
      fi
      exit 1
    fi

    # Process the JSON secret to replace underscores and periods in keys.
    # jq's stderr is routed to the temp file (not surfaced) because parse errors
    # can echo fragments of the input - i.e. the secret - so neither the captured
    # output nor jq's diagnostics are safe to print.
    if ! _secret=$(process_json_to_shell_vars "$_secret" 2>"$_vault_stderr"); then
      echo "Failed to parse JSON secret from $key" >&2
      echo "JSON parse error: details suppressed to avoid leaking secret material" >&2
      exit 1
    fi
  else
    # YAML output - apply sed transformation. Vault's stderr is redirected to a
    # file (not merged into the piped stdout) so a failure never feeds secret
    # bytes through sed, and so the error handler can surface stderr only.
    if ! _secret=$(vault kv get -address="$server" -field=data -format=yaml "$key" 2>"$_vault_stderr" | \
      sed -r '
          s/: /=/;       # Replace ':' with '='
          s/\"/\\"/g;    # Escape double quotes
          s/\$/\\$/g;    # Escape dollar signs
          s/=(.*)$/="\1"/g; # Enclose values in double quotes
      '); then

      # Surface only Vault's stderr - never the captured stdout, which holds the secret.
      vault_error=$(cat "$_vault_stderr")
      echo "Failed to download secret from $key" >&2
      echo "Vault error: $vault_error" >&2

      # Additional context for common errors
      if [[ "$vault_error" =~ "EOF" ]]; then
        echo "EOF error often indicates network connectivity issues or server problems" >&2
      elif [[ "$vault_error" =~ "permission denied" ]]; then
        echo "Permission denied - check if the token has access to this secret path" >&2
      elif [[ "$vault_error" =~ "path not found" ]]; then
        echo "Secret path not found - verify the path exists in Vault" >&2
      fi

      exit 1
    fi

    # Check if the first character of the _secret variable is a '{'
    if [[ "${_secret:0:1}" == "{" ]]; then
      # The YAML output contains JSON, handle accordingly

      # Retrieve the secret from Vault as JSON format instead. Same hardening as
      # the download paths above: isolate Vault's stderr and check for failure so
      # a mid-transfer error can never feed secret bytes into the error handler.
      if ! _secret=$(vault kv get -address="$server" -field=data -format=json "$key" 2>"$_vault_stderr"); then
        vault_error=$(cat "$_vault_stderr")
        echo "Failed to download secret from $key" >&2
        echo "Vault error: $vault_error" >&2
        exit 1
      fi

      # Process the JSON secret to replace underscores and periods in keys
      if ! _secret=$(process_json_to_shell_vars "$_secret" 2>"$_vault_stderr"); then
        echo "Failed to parse JSON secret from $key" >&2
        echo "JSON parse error: details suppressed to avoid leaking secret material" >&2
        exit 1
      fi
    fi
  fi

  echo "$_secret"
}

ssh_key_download() {
  local server="$1"
  local key="$2"

  # SSH Keys must be stored as a single key inside a Vault secret named "ssh_key"
  if ! _secret="$(vault kv get -address="${server}" -field=ssh_key "${key}")"; then
    echo "Failed to download secrets"
    exit 1
  fi
  echo "$_secret"
}

add_ssh_private_key_to_agent() {
  local ssh_key="$1"

  if [[ -z "${SSH_AGENT_PID:-}" ]]; then
    echo "Starting an ephemeral ssh-agent" >&2
    eval "$(ssh-agent -s)"
    export EPHEMERAL_SSH_AGENT_PID="${SSH_AGENT_PID}"
  fi

  echo "Loading ssh-key into ssh-agent (pid ${SSH_AGENT_PID:-})" >&2

  echo "$ssh_key" | env SSH_ASKPASS="/bin/false" ssh-add -
}

grep_secrets() {
  grep -E 'private_ssh_key|id_rsa_github|env|environment|git-credentials$' "$@"
}

# ---------------------------------------------------------------------------
# Secret redaction - register all plugin-fetched secrets with the Buildkite
# agent's log redactor so literal values are scrubbed from job output.
# ---------------------------------------------------------------------------

# Probe once per hook run.  Returns 0 if buildkite-agent redactor add is
# available, 1 otherwise (with a one-time warning on stderr).
_REDACTOR_SUPPORTED=""
_detect_redactor() {
  if ! command -v buildkite-agent >/dev/null 2>&1; then
    echo "+++ :warning: buildkite-agent not found in PATH" >&2
    echo "    Secrets fetched by this plugin will NOT be registered with the" >&2
    echo "    agent's log redactor, so any secret value that is later printed" >&2
    echo "    (set -x, cat \$file, child process output, etc.) may appear in" >&2
    echo "    build logs verbatim." >&2
    echo "    Recommendation: ensure buildkite-agent v3.55 or newer is on PATH" >&2
    echo "    in the environment hook to enable automatic secret redaction." >&2
    echo "    The plugin will continue without redaction." >&2
    return 1
  fi
  if ! buildkite-agent redactor --help >/dev/null 2>&1; then
    echo "+++ :warning: buildkite-agent redactor subcommand unavailable" >&2
    echo "    Secrets fetched by this plugin will NOT be registered with the" >&2
    echo "    agent's log redactor, so any secret value that is later printed" >&2
    echo "    (set -x, cat \$file, child process output, etc.) may appear in" >&2
    echo "    build logs verbatim." >&2
    echo "    Recommendation: upgrade buildkite-agent to v3.55 or newer to" >&2
    echo "    enable automatic secret redaction." >&2
    echo "    The plugin will continue without redaction." >&2
    return 1
  fi
  return 0
}

_redactor_supported() {
  if [[ -z "$_REDACTOR_SUPPORTED" ]]; then
    if _detect_redactor; then
      _REDACTOR_SUPPORTED="yes"
    else
      _REDACTOR_SUPPORTED="no"
    fi
  fi
  [[ "$_REDACTOR_SUPPORTED" == "yes" ]]
}

# Env var names whose live values to register with the redactor.
_PLUGIN_REDACT_NAMES=()
# Parallel arrays for literal secrets (SSH key bytes, file-type field content)
# that never appear in env vars.
_PLUGIN_REDACT_LITERAL_LABELS=()
_PLUGIN_REDACT_LITERAL_VALUES=()
# Counter for unique SSH key labels when multiple keys are discovered.
_PLUGIN_SSH_KEY_INDEX=0

# Track an env var name to be registered with the redactor at end-of-hook.
track_redacted_env() {
  local name
  for name in "$@"; do
    [[ -z "$name" ]] && continue
    _PLUGIN_REDACT_NAMES+=("$name")
  done
}

# Track a raw literal value (non-env) to be registered with the redactor.
# label must be unique within a hook run; value is the secret bytes.
track_redacted_literal() {
  local label="$1"
  local value="$2"
  [[ -z "$value" ]] && return 0
  _PLUGIN_REDACT_LITERAL_LABELS+=("$label")
  _PLUGIN_REDACT_LITERAL_VALUES+=("$value")
}

# Build a JSON object from (labels, values) parallel arrays and pipe it to
# buildkite-agent redactor add --format=json in a single invocation.
# Used by both redact_tracked_secrets and git-credential-vault-secrets.
#
# Secret values are never passed as command-line arguments (which would expose
# them in /proc/*/cmdline). Each value is piped through jq -Rs . via stdin to
# produce a JSON string literal, then assembled in a bash string.
_build_and_send_redactor_payload() {
  local -n _labels="$1"
  local -n _values="$2"
  local i label value k_json v_json json_pairs=""
  for ((i = 0; i < ${#_labels[@]}; i++)); do
    label="${_labels[$i]}"
    value="${_values[$i]}"
    [[ -z "$value" ]] && continue
    k_json="$(printf '%s' "$label" | jq -Rs .)"
    v_json="$(printf '%s' "$value" | jq -Rs .)"
    [[ -n "$json_pairs" ]] && json_pairs+=","
    json_pairs+="${k_json}:${v_json}"
  done
  [[ -z "$json_pairs" ]] && return 0
  # The buildkite-agent redactor reads secrets from stdin when no file
  # argument is given.  Do NOT pass "-": v3.114 (and likely others) do not
  # treat "-" as a stdin alias and will fail with "no such file or
  # directory: -".  Surface any non-zero exit so silent registration
  # failures (which leave secrets unredacted) cannot regress unnoticed.
  local _redactor_rc=0
  local _redactor_stderr
  _redactor_stderr=$(printf '{%s}' "$json_pairs" | buildkite-agent redactor add --format=json 2>&1 >/dev/null) || _redactor_rc=$?
  if [[ $_redactor_rc -ne 0 ]]; then
    echo "+++ :warning: buildkite-agent redactor add failed (rc=$_redactor_rc)" >&2
    [[ -n "$_redactor_stderr" ]] && echo "$_redactor_stderr" | sed 's/^/    /' >&2
  fi
}

# Call once at end of the environment hook to register all tracked secrets.
redact_tracked_secrets() {
  _redactor_supported || return 0

  local -a all_labels=()
  local -a all_values=()
  local name i

  for name in "${_PLUGIN_REDACT_NAMES[@]}"; do
    [[ -z "${!name+set}" ]] && continue
    all_labels+=("$name")
    all_values+=("${!name}")
  done

  for ((i = 0; i < ${#_PLUGIN_REDACT_LITERAL_LABELS[@]}; i++)); do
    all_labels+=("${_PLUGIN_REDACT_LITERAL_LABELS[$i]}")
    all_values+=("${_PLUGIN_REDACT_LITERAL_VALUES[$i]}")
  done

  [[ "${#all_labels[@]}" -eq 0 ]] && return 0
  _build_and_send_redactor_payload all_labels all_values
}
