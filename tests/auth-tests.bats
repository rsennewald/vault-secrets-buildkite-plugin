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
    "write -field=token auth/jwt/login role=buildkite jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

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
    "write -field=token auth/jwt/login role=buildkite jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

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
    "write -field=token auth/jwt/login role=buildkite jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

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
    "write -field=token auth/jwt/login role=bkbkbk jwt=llamas : echo 'Successfully authenticated.'"\
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

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
    "write -field=token auth/custom-jwt/login role=buildkite jwt=llamas : echo vault-token" \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

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