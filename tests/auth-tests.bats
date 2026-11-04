#!/usr/bin/env bats

load "${BATS_PLUGIN_PATH}/load.bash"

# export SSH_AGENT_STUB_DEBUG=/dev/tty
# export SSH_ADD_STUB_DEBUG=/dev/tty
# export VAULT_STUB_DEBUG=/dev/tty
# export CURL_STUB_DEBUG=/dev/tty
# export GIT_STUB_DEBUG=/dev/tty

setup() {
  # if this is not defined, the hook will try to use EC2 metadata to get the instance role
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME='role'
  export TMPDIR="$BATS_TEST_TMPDIR"
}

@test "approle auth method" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export VAULT_SECRET_ID=abcde12345
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID=buildkite
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=approle

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/approle/login role_id=buildkite secret_id=abcde12345 : echo 'Successfully authenticated with Role ID ${6}'"  \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with RoleID'

  unstub vault
}

@test "aws auth method with role name" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="llamas"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with IAM Role'

  unstub vault
}

@test "aws auth using instance IAM role" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PIPELINE_SLUG=testpipe

  # force check
  unset BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  stub curl \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials : echo llamas"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with IAM Role'

  unstub vault
  unstub curl
}

@test "auth using jwt and default env var" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export VAULT_JWT=llamas
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/jwt/login role=buildkite jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "token revoke -address=https://vault_svr_url -self : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with JWT'

  unstub vault
}

@test "auth using jwt with default jwt values" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export VAULT_JWT=llamas
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/jwt/login role=buildkite jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "token revoke -address=https://vault_svr_url -self : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with JWT'

  unstub vault
}

@test "auth using jwt and jwt_var option set" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV=VERY_COOL
  export VERY_COOL=llamas
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/jwt/login role=buildkite jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "token revoke -address=https://vault_svr_url -self : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with JWT'

  unstub vault
}

@test "auth using jwt with role and jwt_var set" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV=VERY_COOL
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ROLE="bkbkbk"
  export VERY_COOL=llamas
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/jwt/login role=bkbkbk jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "token revoke -address=https://vault_svr_url -self : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with JWT'

  unstub vault
}

#-------
# Phase 2: AWS auth enhancements (credential prefix, mount, header)

@test "aws auth with credential-name-prefix reads prefixed env vars" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_CREDENTIAL_NAME_PREFIX="VAULT_AUTH_"
  export VAULT_AUTH_AWS_ACCESS_KEY_ID="AKIA_FAKE"
  export VAULT_AUTH_AWS_SECRET_ACCESS_KEY="SECRET_FAKE"
  export VAULT_AUTH_AWS_SESSION_TOKEN="TOKEN_FAKE"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci aws_access_key_id=AKIA_FAKE aws_secret_access_key=SECRET_FAKE aws_security_token=TOKEN_FAKE : echo vault-token-123" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Using AWS credentials from VAULT_AUTH_AWS_"
  assert_output --partial "Successfully authenticated with IAM Role"

  unstub vault
}

@test "aws auth with credential-name-prefix fails when prefixed vars missing" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_CREDENTIAL_NAME_PREFIX="VAULT_AUTH_"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "AWS credentials not found with prefix"
  assert_output --partial "Ensure the aws-assume-role-with-web-identity plugin runs before this plugin"
}

@test "aws auth without credential-name-prefix uses standard credential chain" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="llamas"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Successfully authenticated with IAM Role"
  refute_output --partial "Using AWS credentials from"

  unstub vault
}

@test "aws auth with credential-name-prefix combined with mount and header" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="svc-buildkite-job-poc"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_CREDENTIAL_NAME_PREFIX="VAULT_AUTH_"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_HEADER_VALUE="zvault.zooxlabs.com"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT="zooxlabs"
  export VAULT_AUTH_AWS_ACCESS_KEY_ID="AKIA_FAKE"
  export VAULT_AUTH_AWS_SECRET_ACCESS_KEY="SECRET_FAKE"
  export VAULT_AUTH_AWS_SESSION_TOKEN="TOKEN_FAKE"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=svc-buildkite-job-poc header_value=zvault.zooxlabs.com mount=zooxlabs aws_access_key_id=AKIA_FAKE aws_secret_access_key=SECRET_FAKE aws_security_token=TOKEN_FAKE : echo vault-token-123" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Successfully authenticated with IAM Role"

  unstub vault
}

@test "aws auth with mount passes mount to vault login" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT="zooxlabs"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci mount=zooxlabs : echo vault-token-123" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Successfully authenticated with IAM Role"

  unstub vault
}

@test "aws auth with header_value passes header to vault login" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_HEADER_VALUE="zvault.zooxlabs.com"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci header_value=zvault.zooxlabs.com : echo vault-token-123" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Successfully authenticated with IAM Role"

  unstub vault
}

@test "approle auth with custom mount" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export VAULT_SECRET_ID=abcde12345
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID=buildkite
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=approle
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT=custom-approle

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/custom-approle/login role_id=buildkite secret_id=abcde12345 : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with RoleID'

  unstub vault
}

@test "jwt auth with custom mount" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export VAULT_JWT=llamas
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT=custom-jwt

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/custom-jwt/login role=buildkite jwt=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "token revoke -address=https://vault_svr_url -self : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with JWT'

  unstub vault
}

@test "aws auth fails when vault login fails" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci : exit 1"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "Failed to get vault token"

  unstub vault
}

#-------
# Phase 3: Cert-based on-prem bootstrap

@test "cert auth fails if only cert-path is set" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="/etc/pki/cert.crt"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "cert-path and cert-key-path must both be set"
}

@test "cert auth fails if only cert-key-path is set" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="/etc/pki/cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "cert-path and cert-key-path must both be set"
}

@test "cert auth fails without aws-vault-sts-role" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="/etc/pki/cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="/etc/pki/cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "aws-vault-sts-role is required when using cert-path"
}

@test "cert auth fails if cert file does not exist" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="/nonexistent/cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="/nonexistent/cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "cert-path not found"
}

@test "cert auth fails if cert key file does not exist" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="/nonexistent/cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "cert-key-path not found"

  rm -f "$BATS_TMPDIR/test-cert.crt"
}

@test "cert auth happy path uses cert bootstrap and vault login" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="$BATS_TMPDIR/test-cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"
  echo "dummy-key" > "$BATS_TMPDIR/test-cert.key"

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=cert -client-cert=$BATS_TMPDIR/test-cert.crt -client-key=$BATS_TMPDIR/test-cert.key name=machine-auth-g1 : echo cert-bootstrap-token" \
    "read -address=https://vault_svr_url -format=json aws/sts/my-ci-role : echo '{\"data\":{\"access_key\":\"AKIA_CERT\",\"secret_key\":\"SECRET_CERT\",\"security_token\":\"TOKEN_CERT\"}}'" \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci aws_access_key_id=AKIA_CERT aws_secret_access_key=SECRET_CERT aws_security_token=TOKEN_CERT : echo vault-token-456" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "On-prem detected: using cert-based bootstrap"
  assert_output --partial "Authenticating to Vault via cert auth"
  assert_output --partial "Reading AWS credentials from Vault AWS secrets engine"
  assert_output --partial "Successfully authenticated with IAM Role"

  rm -f "$BATS_TMPDIR/test-cert.crt" "$BATS_TMPDIR/test-cert.key"
  unstub vault
}

@test "cert auth with custom cert mount" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="$BATS_TMPDIR/test-cert.key"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_MOUNT="custom-cert-mount"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"
  echo "dummy-key" > "$BATS_TMPDIR/test-cert.key"

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=cert -client-cert=$BATS_TMPDIR/test-cert.crt -client-key=$BATS_TMPDIR/test-cert.key name=custom-cert-mount : echo cert-bootstrap-token" \
    "read -address=https://vault_svr_url -format=json aws/sts/my-ci-role : echo '{\"data\":{\"access_key\":\"AKIA_CERT\",\"secret_key\":\"SECRET_CERT\",\"security_token\":\"TOKEN_CERT\"}}'" \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci aws_access_key_id=AKIA_CERT aws_secret_access_key=SECRET_CERT aws_security_token=TOKEN_CERT : echo vault-token-456" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "cert auth (mount: custom-cert-mount)"
  assert_output --partial "Successfully authenticated with IAM Role"

  rm -f "$BATS_TMPDIR/test-cert.crt" "$BATS_TMPDIR/test-cert.key"
  unstub vault
}

@test "cert auth with mount and header passes them to vault login" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_HEADER_VALUE="zvault.zooxlabs.com"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT="zooxlabs"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="$BATS_TMPDIR/test-cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"
  echo "dummy-key" > "$BATS_TMPDIR/test-cert.key"

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=cert -client-cert=$BATS_TMPDIR/test-cert.crt -client-key=$BATS_TMPDIR/test-cert.key name=machine-auth-g1 : echo cert-bootstrap-token" \
    "read -address=https://vault_svr_url -format=json aws/sts/my-ci-role : echo '{\"data\":{\"access_key\":\"AKIA_CERT\",\"secret_key\":\"SECRET_CERT\",\"security_token\":\"TOKEN_CERT\"}}'" \
    "login -field=token -address=https://vault_svr_url -method=aws role=my-team-ci header_value=zvault.zooxlabs.com mount=zooxlabs aws_access_key_id=AKIA_CERT aws_secret_access_key=SECRET_CERT aws_security_token=TOKEN_CERT : echo vault-token-789" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Successfully authenticated with IAM Role"

  rm -f "$BATS_TMPDIR/test-cert.crt" "$BATS_TMPDIR/test-cert.key"
  unstub vault
}

@test "cert auth fails when vault aws engine returns bad response" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="$BATS_TMPDIR/test-cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"
  echo "dummy-key" > "$BATS_TMPDIR/test-cert.key"

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=cert -client-cert=$BATS_TMPDIR/test-cert.crt -client-key=$BATS_TMPDIR/test-cert.key name=machine-auth-g1 : echo cert-bootstrap-token" \
    "read -address=https://vault_svr_url -format=json aws/sts/my-ci-role : echo '{\"data\":{}}'"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "Failed to extract credentials from Vault AWS engine response"

  rm -f "$BATS_TMPDIR/test-cert.crt" "$BATS_TMPDIR/test-cert.key"
  unstub vault
}

@test "cert auth fails when vault cert login fails" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="$BATS_TMPDIR/test-cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"
  echo "dummy-key" > "$BATS_TMPDIR/test-cert.key"

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=cert -client-cert=$BATS_TMPDIR/test-cert.crt -client-key=$BATS_TMPDIR/test-cert.key name=machine-auth-g1 : exit 1"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "Cert auth failed"

  rm -f "$BATS_TMPDIR/test-cert.crt" "$BATS_TMPDIR/test-cert.key"
  unstub vault
}

@test "cert auth fails when vault aws sts read fails" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=aws
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME="my-team-ci"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_VAULT_STS_ROLE="my-ci-role"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_PATH="$BATS_TMPDIR/test-cert.crt"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_CERT_KEY_PATH="$BATS_TMPDIR/test-cert.key"
  export BUILDKITE_PIPELINE_SLUG=testpipe

  echo "dummy-cert" > "$BATS_TMPDIR/test-cert.crt"
  echo "dummy-key" > "$BATS_TMPDIR/test-cert.key"

  stub vault \
    "login -field=token -address=https://vault_svr_url -method=cert -client-cert=$BATS_TMPDIR/test-cert.crt -client-key=$BATS_TMPDIR/test-cert.key name=machine-auth-g1 : echo cert-bootstrap-token" \
    "read -address=https://vault_svr_url -format=json aws/sts/my-ci-role : exit 1"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "Failed to get AWS credentials via Vault AWS engine"

  rm -f "$BATS_TMPDIR/test-cert.crt" "$BATS_TMPDIR/test-cert.key"
  unstub vault
}

@test "max-retries option exports VAULT_MAX_RETRIES for vault calls" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_PLUGIN_VAULT_SECRETS_MAX_RETRIES=5
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=approle
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID=buildkite
  export VAULT_SECRET_ID=abcde12345
  unset VAULT_MAX_RETRIES

  # the stub fails unless the retry setting reached the vault process
  stub vault \
    'write -field=token -address=https://vault_svr_url auth/approle/login role_id=buildkite secret_id=abcde12345 : [ "$VAULT_MAX_RETRIES" = 5 ] && echo token' \
    'kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0' \
    'kv list -address=https://vault_svr_url -format=yaml foobar : exit 0'

  run bash -c "$PWD/hooks/environment"

  assert_success
  assert_output --partial 'Successfully authenticated with RoleID'

  unstub vault
}

@test "VAULT_MAX_RETRIES from the agent environment is left alone when max-retries is unset" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=approle
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID=buildkite
  export VAULT_SECRET_ID=abcde12345
  export VAULT_MAX_RETRIES=7

  stub vault \
    'write -field=token -address=https://vault_svr_url auth/approle/login role_id=buildkite secret_id=abcde12345 : [ "$VAULT_MAX_RETRIES" = 7 ] && echo token' \
    'kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0' \
    'kv list -address=https://vault_svr_url -format=yaml foobar : exit 0'

  run bash -c "$PWD/hooks/environment"

  assert_success

  unstub vault
}

@test "jwt auth requests a Buildkite OIDC token when no JWT is given, then pre-exit revokes the token" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_MOUNT=buildkite
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ROLE=my-team-ci
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_JOB_ID=job-1
  export TMPDIR="$BATS_TEST_TMPDIR"
  unset VAULT_JWT VAULT_ADDR

  stub buildkite-agent \
    "oidc request-token --audience https://vault_svr_url --lifetime 300 : echo minted-jwt" \
    "redactor --help : exit 1"
  stub vault \
    "write -field=token -address=https://vault_svr_url auth/buildkite/login role=my-team-ci jwt=minted-jwt : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "token revoke -address=https://vault_svr_url -self : test \"\$VAULT_TOKEN\" = vault-token"

  run bash -c "source $PWD/hooks/environment && echo \"addr=\$VAULT_ADDR token=\$VAULT_TOKEN\" && stat -c %a $TMPDIR/vault-secrets-plugin-job-1.token && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Successfully authenticated with JWT'
  assert_output --partial 'addr=https://vault_svr_url token=vault-token'
  assert_output --partial $'\n600\n'
  assert_output --partial 'Revoking the Vault token'
  refute_output --partial 'Could not revoke'
  assert_file_not_exists "$TMPDIR/vault-secrets-plugin-job-1.token"

  unstub buildkite-agent
  unstub vault
}

@test "pre-exit revokes the jwt token even when the environment hook failed after logging in" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH=kv2/team/forbidden
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME=x
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV=X
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_JOB_ID=job-2
  export TMPDIR="$BATS_TEST_TMPDIR"
  export VAULT_JWT=llamas

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/jwt/login role=buildkite jwt=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json kv2/team/forbidden : echo 'permission denied' >&2; exit 2" \
    "token revoke -address=https://vault_svr_url -self : test \"\$VAULT_TOKEN\" = vault-token"

  run bash -c "$PWD/hooks/environment"
  assert_failure
  assert_output --partial 'Failed to fetch secret from kv2/team/forbidden'

  run bash -c "$PWD/hooks/pre-exit"
  assert_success
  assert_output --partial 'Revoking the Vault token'
  refute_output --partial 'Could not revoke'

  unstub vault
}

@test "jwt auth fails when the Buildkite OIDC token request fails" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export BUILDKITE_PIPELINE_SLUG=testpipe
  unset VAULT_JWT

  stub buildkite-agent \
    "oidc request-token --audience https://vault_svr_url --lifetime 300 : exit 1"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial 'Failed to request a Buildkite OIDC token'

  unstub buildkite-agent
}

@test "pre-exit keeps going when revoking the Vault token fails" {
  export BUILDKITE_JOB_ID=job-3
  export TMPDIR="$BATS_TEST_TMPDIR"
  printf '%s\n%s\n' https://vault_svr_url vault-token >"$TMPDIR/vault-secrets-plugin-job-3.token"

  stub vault \
    "token revoke -address=https://vault_svr_url -self : exit 2"

  run bash -c "$PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Could not revoke the Vault token'
  assert_file_not_exists "$TMPDIR/vault-secrets-plugin-job-3.token"

  unstub vault
}

@test "pre-exit leaves a Vault token the plugin did not mint alone" {
  export BUILDKITE_JOB_ID=job-4
  export TMPDIR="$BATS_TEST_TMPDIR"
  export VAULT_TOKEN=someone-elses-token

  run bash -c "$PWD/hooks/pre-exit"

  assert_success
  refute_output --partial 'Revoking the Vault token'
}

@test "hook: pre-command skips the environment hook and loads secrets in pre-command" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=false
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt
  export BUILDKITE_PLUGIN_VAULT_SECRETS_HOOK=pre-command
  export BUILDKITE_PIPELINE_SLUG=testpipe
  export BUILDKITE_JOB_ID=job-5
  export VAULT_JWT=llamas

  run bash -c "$PWD/hooks/environment"
  assert_success
  assert_output 'Skipping environment hook; secrets load in the pre-command hook'

  stub vault \
    "write -field=token -address=https://vault_svr_url auth/jwt/login role=buildkite jwt=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "source $PWD/hooks/pre-command && echo \"addr=\$VAULT_ADDR token=\$VAULT_TOKEN\""
  assert_success
  assert_output --partial 'Successfully authenticated with JWT'
  assert_output --partial 'addr=https://vault_svr_url token=vault-token'

  unstub vault
}

@test "pre-command does nothing without hook: pre-command" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD=jwt

  run bash -c "$PWD/hooks/pre-command"

  assert_success
  assert_output ''
}

@test "pre-exit still cleans up when the token file is truncated" {
  export BUILDKITE_JOB_ID=job-6
  export TMPDIR="$BATS_TEST_TMPDIR"
  printf '%s\n' https://vault_svr_url >"$TMPDIR/vault-secrets-plugin-job-6.token"
  export SECRET_TMPDIR="$BATS_TEST_TMPDIR/secret-files"
  mkdir "$SECRET_TMPDIR"

  run bash -c "$PWD/hooks/pre-exit"

  assert_success
  assert_output --partial 'Could not revoke the Vault token'
  assert_output --partial 'Cleaning up secret files'
  assert_file_not_exists "$TMPDIR/vault-secrets-plugin-job-6.token"
  assert_dir_not_exists "$SECRET_TMPDIR"
}
