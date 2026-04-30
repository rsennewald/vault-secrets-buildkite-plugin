#!/usr/bin/env bats

# Tests for the buildkite-agent redactor integration added in feat/vault-redactor.
#
# These tests verify:
#   - Capability probe: missing binary -> warn and continue
#   - Capability probe: pre-v3.55 (missing redactor subcommand) -> warn and continue
#   - Capability probe: success path -> no warning
#   - env/environment secrets: tracked env var names appear in JSON payload
#   - Only plugin-tracked keys in payload (no PATH, BUILDKITE_*, etc.)
#   - SSH key bytes: tracked as literal under _VAULT_PLUGIN_SSH_KEY_0
#   - type=env field: env var name in payload
#   - type=file field: file content tracked as _VAULT_PLUGIN_FILE_*;
#                      path env var NOT in payload as a key
#   - Exactly one redactor add call per hook run
#   - VAULT_TOKEN tracked after vault_auth (approle path)
#   - git-credential-vault-secrets: one bulk JSON call before IOFMT output

# export VAULT_STUB_DEBUG=/dev/tty
# export BUILDKITE_AGENT_STUB_DEBUG=/dev/tty

setup() {
  load "${BATS_PLUGIN_PATH}/load.bash"

  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false

  # Temp file for capturing the redactor add payload between stub and assertion.
  REDACT_PAYLOAD_FILE="${BATS_TEST_TMPDIR}/redact-payload.json"
}

# ---------------------------------------------------------------------------
# Helper: stub buildkite-agent with working redactor (probe + add capture).
# Usage: _stub_buildkite_agent_redactor
# The stub writes the JSON payload piped to "redactor add" to REDACT_PAYLOAD_FILE.
# ---------------------------------------------------------------------------
_stub_buildkite_agent_redactor() {
  stub buildkite-agent \
    "redactor --help : true" \
    "redactor add --format=json : cat > '${REDACT_PAYLOAD_FILE}'"
}

# ---------------------------------------------------------------------------
# Helper: assert a key IS present in the captured JSON payload.
# ---------------------------------------------------------------------------
_assert_payload_key() {
  local key="$1"
  run jq --arg k "$key" 'has($k)' "${REDACT_PAYLOAD_FILE}"
  assert_success
  assert_output "true"
}

# ---------------------------------------------------------------------------
# Helper: assert a key is NOT present in the captured JSON payload.
# ---------------------------------------------------------------------------
_refute_payload_key() {
  local key="$1"
  run jq --arg k "$key" 'has($k)' "${REDACT_PAYLOAD_FILE}"
  assert_success
  assert_output "false"
}

# ---------------------------------------------------------------------------
# Helper: assert a key/value pair IS in the captured JSON payload.
# ---------------------------------------------------------------------------
_assert_payload_value() {
  local key="$1"
  local expected_value="$2"
  run jq -r --arg k "$key" '.[$k] // empty' "${REDACT_PAYLOAD_FILE}"
  assert_success
  assert_output "$expected_value"
}

# ===========================================================================
# Capability probe tests
# ===========================================================================

@test "Redaction: missing buildkite-agent binary emits warning and hook still succeeds" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo 'MY_SECRET: val'"

  # Run without a buildkite-agent stub so the binary is not on PATH.
  run bash -c "PATH=${PATH} $PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "buildkite-agent not found in PATH"
  assert_output --partial "The plugin will continue without redaction"

  unstub vault
}

@test "Redaction: pre-v3.55 agent (redactor subcommand missing) emits warning and hook still succeeds" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo 'MY_SECRET: val'"

  # Stub buildkite-agent to fail on the redactor --help probe (simulates pre-v3.55).
  stub buildkite-agent \
    "redactor --help : exit 1"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "buildkite-agent redactor subcommand unavailable"
  assert_output --partial "upgrade buildkite-agent to v3.55"
  assert_output --partial "The plugin will continue without redaction"

  unstub vault
  unstub buildkite-agent
}

@test "Redaction: success path emits no redaction warning" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo 'MY_SECRET: val'"

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  refute_output --partial "not found in PATH"
  refute_output --partial "subcommand unavailable"
  refute_output --partial "without redaction"

  unstub vault
  unstub buildkite-agent
}

# ===========================================================================
# Env secret tracking
# ===========================================================================

@test "Redaction: env secret var names appear in redactor payload" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : printf 'MY_SECRET: fooblah\nANOTHER_VAR: baaz'"

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success

  _assert_payload_key "MY_SECRET"
  _assert_payload_value "MY_SECRET" "fooblah"
  _assert_payload_key "ANOTHER_VAR"
  _assert_payload_value "ANOTHER_VAR" "baaz"

  unstub vault
  unstub buildkite-agent
}

@test "Redaction: payload contains only tracked keys, not PATH or BUILDKITE_* vars" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo 'MY_SECRET: supersecret'"

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  _assert_payload_key "MY_SECRET"
  _refute_payload_key "PATH"
  _refute_payload_key "BUILDKITE_PIPELINE_SLUG"
  _refute_payload_key "BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER"

  unstub vault
  unstub buildkite-agent
}

@test "Redaction: exactly one redactor add call per hook run even with multiple env secrets" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'env'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo 'SECRET_A: val_a'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo 'SECRET_B: val_b'"

  # Stub expects exactly one redactor --help probe and one redactor add call.
  # bats-mock will fail the test if extra calls are made.
  stub buildkite-agent \
    "redactor --help : true" \
    "redactor add --format=json : cat > '${REDACT_PAYLOAD_FILE}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  _assert_payload_key "SECRET_A"
  _assert_payload_key "SECRET_B"

  unstub vault
  unstub buildkite-agent
}

# ===========================================================================
# SSH key literal tracking
# ===========================================================================

@test "Redaction: SSH key bytes tracked under _VAULT_PLUGIN_SSH_KEY_0 in payload" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'private_ssh_key'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/testpipe/private_ssh_key : echo 'FAKE_SSH_KEY_CONTENT'"

  stub ssh-agent \
    "-s : echo 'SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.123; export SSH_AUTH_SOCK; SSH_AGENT_PID=123; export SSH_AGENT_PID; echo Agent pid 123;'"

  stub ssh-add \
    "- : exit 0"

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  _assert_payload_key "_VAULT_PLUGIN_SSH_KEY_0"
  _assert_payload_value "_VAULT_PLUGIN_SSH_KEY_0" "FAKE_SSH_KEY_CONTENT"
  _refute_payload_key "_VAULT_PLUGIN_SSH_KEY_1"

  unstub vault
  unstub ssh-agent
  unstub ssh-add
  unstub buildkite-agent
}

# ===========================================================================
# Explicit secrets: type=env
# ===========================================================================

@test "Redaction: type=env field tracked by env var name in payload" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/db-creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="password"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="DB_PASSWORD"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/db-creds : echo '{\"password\":\"s3cr3t\"}'"

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  _assert_payload_key "DB_PASSWORD"
  _assert_payload_value "DB_PASSWORD" "s3cr3t"

  unstub vault
  unstub buildkite-agent
}

# ===========================================================================
# Explicit secrets: type=file
# ===========================================================================

@test "Redaction: type=file field content tracked under _VAULT_PLUGIN_FILE_* but path env var NOT in payload" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/gcp-sa"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="json"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="GOOGLE_APPLICATION_CREDENTIALS"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_TYPE="file"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/gcp-sa : echo '{\"json\":\"{\\\"type\\\":\\\"service_account\\\"}\"}'  "

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  # Content is tracked under the synthetic literal key.
  _assert_payload_key "_VAULT_PLUGIN_FILE_GOOGLE_APPLICATION_CREDENTIALS"
  # The path env var itself must NOT be a key in the payload.
  _refute_payload_key "GOOGLE_APPLICATION_CREDENTIALS"

  unstub vault
  unstub buildkite-agent
}

# ===========================================================================
# VAULT_TOKEN tracking after vault_auth
# ===========================================================================

@test "Redaction: VAULT_TOKEN tracked in payload after approle auth" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export VAULT_SECRET_ID=abcde12345
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID=buildkite
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=approle

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/approle/login role_id=buildkite secret_id=abcde12345 : echo 'fake-vault-token'" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  _stub_buildkite_agent_redactor

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  _assert_payload_key "VAULT_TOKEN"
  _assert_payload_value "VAULT_TOKEN" "fake-vault-token"

  unstub vault
  unstub buildkite-agent
}

# ===========================================================================
# git-credential-vault-secrets redaction
# ===========================================================================

@test "Redaction: git-credential-vault-secrets registers password before emitting IOFMT output" {
  stub vault \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/git-credentials : echo 'https://user:s3cr3tpwd@host.io'"

  stub buildkite-agent \
    "redactor --help : true" \
    "redactor add --format=json : cat > '${REDACT_PAYLOAD_FILE}'"

  run ./git-credential-vault-secrets "https://vault_svr_url" "data/buildkite/testpipe/git-credentials"

  assert_success

  # IOFMT output should still be intact.
  assert_output --partial "protocol=https"
  assert_output --partial "host=host.io"
  assert_output --partial "username=user"
  assert_output --partial "password=s3cr3tpwd"

  # Password (and user) should be in the redactor payload.
  _assert_payload_key "_VAULT_PLUGIN_GIT_PASSWORD_0"
  _assert_payload_value "_VAULT_PLUGIN_GIT_PASSWORD_0" "s3cr3tpwd"
  _assert_payload_key "_VAULT_PLUGIN_GIT_USER_0"
  _assert_payload_value "_VAULT_PLUGIN_GIT_USER_0" "user"

  unstub vault
  unstub buildkite-agent
}

@test "Redaction: git-credential-vault-secrets without redactor support still outputs IOFMT" {
  stub vault \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/git-credentials : echo 'https://user:s3cr3tpwd@host.io'"

  stub buildkite-agent \
    "redactor --help : exit 1"

  run ./git-credential-vault-secrets "https://vault_svr_url" "data/buildkite/testpipe/git-credentials"

  assert_success
  assert_output --partial "protocol=https"
  assert_output --partial "password=s3cr3tpwd"
  assert_output --partial "buildkite-agent redactor subcommand unavailable"

  unstub vault
  unstub buildkite-agent
}
