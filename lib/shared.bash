#!/bin/bash
set -ueo pipefail

[ -z "${TMPDIR:-}" ] && TMPDIR=${TMPDIR:-/tmp}

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

        echo "Successfully authenticated with IAM Role ${aws_role_name} and updated vault token"
      ;;

    jwt)
        echo "--- performing JWT authentication"
        if [ -z "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV:-}" ]; then
          jwt_var="${VAULT_JWT?No JWT found}"
        else
          jwt_var="${!BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV}"
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
        VAULT_TOKEN=$(vault write -field=token "$jwt_path" \
          role="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ROLE:-"buildkite"}" \
          jwt="${jwt_var:-}") || jwt_rc=$?

        if [[ $jwt_rc -ne 0 ]]; then
          echo "+++ Failed to get vault token" >&2
          exit $jwt_rc
        fi

        export VAULT_TOKEN

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
  ' 2>&1
}

secret_download() {
  local server="$1"
  local key="$2"
  # should default to YAML, but allows the option for getting JSON output.
  local output="${BUILDKITE_PLUGIN_VAULT_SECRETS_OUTPUT:-"yaml"}"

  # Attempt to retrieve the secret from Vault with detailed error capture
  local vault_error

  if [[ "${output}" == "json" ]]; then
    # JSON output - no sed transformation needed
    if ! _secret=$(vault kv get -address="$server" -field=data -format=json "$key" 2>&1); then
      vault_error=$_secret
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

    # Process the JSON secret to replace underscores and periods in keys
    if ! _secret=$(process_json_to_shell_vars "$_secret"); then
      echo "Failed to parse JSON secret from $key" >&2
      echo "JSON parse error: $_secret" >&2
      exit 1
    fi
  else
    # YAML output - apply sed transformation
    if ! _secret=$(vault kv get -address="$server" -field=data -format=yaml "$key" 2>&1 | \
      sed -r '
          s/: /=/;       # Replace ':' with '='
          s/\"/\\"/g;    # Escape double quotes
          s/\$/\\$/g;    # Escape dollar signs
          s/=(.*)$/="\1"/g; # Enclose values in double quotes
      '); then

      # Capture the vault command error for better debugging
      vault_error=$(vault kv get -address="$server" -field=data -format=yaml "$key" 2>&1)
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

      # Retrieve the secret from Vault as JSON format instead
      _secret=$(vault kv get -address="$server" -field=data -format=json "$key")

      # Process the JSON secret to replace underscores and periods in keys
      if ! _secret=$(process_json_to_shell_vars "$_secret"); then
        echo "Failed to parse JSON secret from $key" >&2
        echo "JSON parse error: $_secret" >&2
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
