#!/usr/bin/env bats

# export SSH_AGENT_STUB_DEBUG=/dev/tty
# export SSH_ADD_STUB_DEBUG=/dev/tty
# export VAULT_STUB_DEBUG=/dev/tty
# export GIT_STUB_DEBUG=/dev/tty

setup() {
  load "${BATS_PLUGIN_PATH}/load.bash"

  export BUILDKITE_PIPELINE_SLUG=testpipe

  export BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER=https://vault_svr_url
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=true
}

#-------
# Default scope
@test "Load default env file from vault server" {
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load default env file containing secrets with special characters from vault server" {
  export TESTDATA="MY_SECRET: \"|- $:fooblah\""

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=|- $:fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load default env file and convert secrets with \": \" pattern from vault server" {
  export TESTDATA="MY_SECRET: \"Likes: llamas\""

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=Likes: llamas"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load default env file from JSON output from vault server" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_OUTPUT="json"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV=true
  export TESTDATA='{"foo": "bar", "test_data2": "llamas"}'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=json data/buildkite/env : echo '${TESTDATA}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "foo=bar"
  refute_output --partial "unsetvar=blah"

  unstub vault
}

@test "Load default env file with a multi-line secret with JSON output from vault server" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_OUTPUT="json"
  export TESTDATA='{"license": "\"something or other \\\n  comment\" another=\"more \\\n  info\" date=\"2020482983\" \\\n  end=\"finished\""}'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=json data/buildkite/env : echo '${TESTDATA}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  unstub vault
}

@test "Load default environment file from vault server" {
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'environment'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/environment : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load default env and environments files from vault server" {
  export TESTDATA_ENV1='MY_SECRET: fooblah'
  export TESTDATA_ENV2='ANOTHER_SECRET: baa'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env environment'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA_ENV1}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/environment : echo ${TESTDATA_ENV2}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

#-------
# Project scope
@test "Load project env file from vault server" {
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'env'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo '${TESTDATA}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load project environment file from vault server" {
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'environment'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/environment : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load project env and environments files from vault server" {
  export TESTDATA_ENV1='MY_SECRET: fooblah'
  export TESTDATA_ENV2='ANOTHER_SECRET: baa'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'env environment'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo ${TESTDATA_ENV1}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/environment : echo ${TESTDATA_ENV2}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

#-------
# Combinations of scopes
@test "Load default and project env files from vault server" {
  export TESTDATA_ENV1='MY_SECRET: fooblah'
  export TESTDATA_ENV2='ANOTHER_SECRET: baa'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'env'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo ${TESTDATA_ENV1}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA_ENV2}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load default and project environment files from vault server" {
  export TESTDATA_ENV1='MY_SECRET: fooblah'
  export TESTDATA_ENV2='ANOTHER_SECRET: baa'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'environment'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'environment'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/environment : echo ${TESTDATA_ENV1}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/environment : echo ${TESTDATA_ENV2}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

#-------
# All scopes and env, environment files
@test "Load env and environments files for project and default from vault server" {
  export TESTDATA_ENV1='MY_SECRET1: baa1'
  export TESTDATA_ENV2='MY_SECRET2: baa2'
  export TESTDATA_ENV3='MY_SECRET3: baa3'
  export TESTDATA_ENV4='MY_SECRET4: baa4'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'env environment'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env environment'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo ${TESTDATA_ENV1}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/environment : echo ${TESTDATA_ENV2}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA_ENV3}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/environment : echo ${TESTDATA_ENV4}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET1=baa1"
  assert_output --partial "MY_SECRET2=baa2"
  assert_output --partial "MY_SECRET3=baa3"
  assert_output --partial "MY_SECRET4=baa4"

  unstub vault
}

#-------
# Git Credentials
@test "Load default git-credentials from vault into GIT_CONFIG_PARAMETERS" {
  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0 " \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo -e '- git-credentials'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Adding git-credentials in data/buildkite/git-credentials as a credential helper"
  assert_output --partial "GIT_CONFIG_PARAMETERS='credential.helper="

  unstub vault
}

@test "Load pipeline git-credentials from vault into GIT_CONFIG_PARAMETERS" {
  export TESTDATA_ENV1='MY_SECRET1: baa1'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo -e '- git-credentials'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Adding git-credentials in data/buildkite/testpipe/git-credentials as a credential helper"
  assert_output --partial "GIT_CONFIG_PARAMETERS='credential.helper="
  unstub vault

  unset TESTDATA_ENV1
  unset BUILDKITE_PLUGIN_VAULT_SECRETS_DUMP_ENV
  unset BUILDKITE_PLUGIN_VAULT_SECRETS_SERVER
  unset BUILDKITE_PIPELINE_SLUG
}

#-------
# ssh-keys
@test "Load default ssh-key from vault into ssh-agent" {
  export TESTDATA='foobar'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=26345"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo -e '- private_ssh_key'" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/private_ssh_key : echo ${TESTDATA}"

  stub ssh-add \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 26345)"
  assert_output --partial "added ssh key"

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Load project ssh-key from vault into ssh-agent" {
  export TESTDATA='foobar'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=26345"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo -e '- private_ssh_key'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/testpipe/private_ssh_key : echo ${TESTDATA}"

  stub ssh-add \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 26345)"
  assert_output --partial "added ssh key"

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Load default and project ssh-keys from vault into ssh-agent" {
  export TESTDATA='foobar'
  export TESTDATA2='foobar2'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=26345"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo -e '- private_ssh_key'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo -e '- private_ssh_key'" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/testpipe/private_ssh_key : echo ${TESTDATA}" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/private_ssh_key : echo ${TESTDATA2}"

  stub ssh-add \
    '- : echo added ssh key' \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 26345)"
  assert_output --partial "added ssh key"

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Load default ssh-key and env from vault" {
  export TESTDATA_KEY='foobar'
  export TESTDATA_ENV='MY_SECRET: fooblah'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=54252"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo -e 'private_ssh_key env'" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/private_ssh_key : echo ${TESTDATA_KEY}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA_ENV}"

  stub ssh-add \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 54252)"
  assert_output --partial "added ssh key"
  assert_output --partial "MY_SECRET=fooblah"

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Load project ssh-key and env from vault" {
  export TESTDATA_KEY='foobar'
  export TESTDATA_ENV='MY_SECRET: fooblah'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=12423"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'private_ssh_key env'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0 " \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/testpipe/private_ssh_key : echo ${TESTDATA_KEY}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo ${TESTDATA_ENV}"

  stub ssh-add \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 12423)"
  assert_output --partial "added ssh key"
  assert_output --partial "MY_SECRET=fooblah"

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Load default ssh-key, env and git-credentials from vault into ssh-agent" {
  export TESTDATA_KEY='foobar'
  export TESTDATA_ENV='MY_SECRET: fooblah'
  export TESTDATA_GIT='me@pass'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=24124"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo -e 'env private_ssh_key git-credentials'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA_ENV}" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/private_ssh_key : echo ${TESTDATA_KEY}"

  stub ssh-add \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 24124)"
  assert_output --partial "added ssh key"
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "Adding git-credentials in data/buildkite/git-credentials as a credential helper"
  assert_output --partial "GIT_CONFIG_PARAMETERS='credential.helper="
  # assert_output --partial "Could not open a connection to your authentication agent"

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Load project ssh-key, env and git-credentials from vault into ssh-agent" {
  export TESTDATA_KEY='foobar'
  export TESTDATA_ENV='MY_SECRET: fooblah'
  export TESTDATA_GIT='me@pass'

  stub ssh-agent "-s : echo export SSH_AGENT_PID=12423"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo -e 'env private_ssh_key git-credentials'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo ${TESTDATA_ENV}" \
    "kv get -address=https://vault_svr_url -field=ssh_key data/buildkite/testpipe/private_ssh_key : echo ${TESTDATA_KEY}"

  stub ssh-add \
    '- : echo added ssh key'

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "ssh-agent (pid 12423)"
  assert_output --partial "added ssh key"
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "Adding git-credentials in data/buildkite/testpipe/git-credentials as a credential helper"
  assert_output --partial "GIT_CONFIG_PARAMETERS='credential.helper="

  unstub ssh-agent
  unstub vault
  unstub ssh-add
}

@test "Dump env secrets" {
  export TESTDATA_ENV_1='TEST_SECRET: foobar'
  export TESTDATA_ENV_2='ANOTHER_SECRET: foo'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo -e 'env'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo '${TESTDATA_ENV_1}'; echo '${TESTDATA_ENV_2}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "TEST_SECRET=foobar"
  assert_output --partial "ANOTHER_SECRET=foo"

  unstub vault
}

@test "test path option" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_PATH=foobar

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml foobar/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml foobar : exit 0"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Checking vault secrets foobar/testpipe"
  assert_output --partial "Checking vault secrets foobar"

  unstub vault
}

@test "Custom Namespace is set in environment hook" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_NAMESPACE=llamas
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Using namespace: llamas"
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load custom secret key from default path" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET="supersecret"
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo '${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET}'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET} : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load custom secret key from project path" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET="supersecret"
  export TESTDATA='MY_SECRET: fooblah'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo '${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET}'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET} : echo ${TESTDATA}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load custom secret key from default and project path" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET="supersecret"
  export TESTDATA='MY_SECRET: fooblah'
  export TESTDATA2='NEW_GROOVE: llamas'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo '${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET}'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo '${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET}'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET} : echo ${TESTDATA}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET} : echo ${TESTDATA2}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "NEW_GROOVE=llamas"
  refute_output --partial "ANOTHER_SECRET=baa"

  unstub vault
}

@test "Load env, environment, and custom secret key files for project and default from vault server" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET="supersecret"

  export TESTDATA_ENV1='MY_SECRET1: baa1'
  export TESTDATA_ENV2='MY_SECRET2: baa2'
  export TESTDATA_ENV3='MY_SECRET3: baa3'
  export TESTDATA_ENV4='MY_SECRET4: baa4'
  export TESTDATA_ENV5='MY_SECRET5: baa5'
  export TESTDATA_ENV6='MY_SECRET6: baa6'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : echo 'env environment ${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET}'" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env environment ${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET}'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/env : echo ${TESTDATA_ENV1}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/environment : echo ${TESTDATA_ENV2}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/testpipe/${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET} : echo ${TESTDATA_ENV3}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo ${TESTDATA_ENV4}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/environment : echo ${TESTDATA_ENV5}" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/${BUILDKITE_PLUGIN_VAULT_SECRETS_SECRET} : echo ${TESTDATA_ENV6}"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET1=baa1"
  assert_output --partial "MY_SECRET2=baa2"
  assert_output --partial "MY_SECRET3=baa3"
  assert_output --partial "MY_SECRET4=baa4"
  assert_output --partial "MY_SECRET5=baa5"
  assert_output --partial "MY_SECRET6=baa6"

  unstub vault
}

@test "Load custom json secret" {
  export TESTDATA='{"MY_SECRET": "fooblah", "OTHER SECRET": "foo bar"}'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo '${TESTDATA}'" \
    "kv get -address=https://vault_svr_url -field=data -format=json data/buildkite/env : echo '${TESTDATA}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "OTHER_SECRET=foo bar"
  refute_output --partial "OTHER SECRET=foobar"
  refute_output --partial "OTHER_SECRET=foobar"

  unstub vault
}

#-------
# Explicit secrets list (Phase 1: field mapping)

@test "Secrets string format dumps all fields (backward compat)" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0="secret/ci/team/db-creds"
  export TESTDATA='DB_USER: admin'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml secret/ci/team/db-creds : echo '${TESTDATA}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Fetching secret (dump-all)"
  assert_output --partial "Evaluating"

  unstub vault
}

@test "Secrets field-mapping mode exports specific fields with custom env names" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="password"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="DATABASE_PASSWORD"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_1_NAME="username"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_1_ENV="DATABASE_USER"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/creds : echo '{\"password\":\"s3cret\",\"username\":\"admin\",\"host\":\"db.example.com\"}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Exported field 'password' as DATABASE_PASSWORD"
  assert_output --partial "Exported field 'username' as DATABASE_USER"
  refute_output --partial "host"

  unstub vault
}

@test "Secrets string format supports multiple secrets" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0="secret/ci/team/db-creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_1="secret/ci/team/api-keys"
  export TESTDATA_DB='DB_USER: admin'
  export TESTDATA_API='API_KEY: abc123'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml secret/ci/team/db-creds : echo '${TESTDATA_DB}'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml secret/ci/team/api-keys : echo '${TESTDATA_API}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Fetching secret (dump-all): secret/ci/team/db-creds"
  assert_output --partial "Fetching secret (dump-all): secret/ci/team/api-keys"

  unstub vault
}

@test "Explicit secrets work alongside auto-discovery" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/db-creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="password"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="DB_PASSWORD"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : echo 'env'" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml data/buildkite/env : echo 'MY_SECRET: fooblah'" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/db-creds : echo '{\"password\":\"s3cret\"}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "MY_SECRET=fooblah"
  assert_output --partial "Exported field 'password' as DB_PASSWORD"

  unstub vault
}

@test "Secrets mixed format: string dump-all and object field-mapped in same list" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0="secret/ci/team/env-creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_1_PATH="secret/ci/team/db-creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_1_FIELDS_0_NAME="password"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_1_FIELDS_0_ENV="DB_PASSWORD"
  export TESTDATA='API_KEY: abc123'

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=yaml secret/ci/team/env-creds : echo '${TESTDATA}'" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/db-creds : echo '{\"password\":\"s3cret\"}'"

  run bash -c "$PWD/hooks/environment && $PWD/hooks/pre-exit"

  assert_success
  assert_output --partial "Fetching secret (dump-all): secret/ci/team/env-creds"
  assert_output --partial "Exported field 'password' as DB_PASSWORD"

  unstub vault
}

@test "Secrets field-mapping fails when env is missing" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="host"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/creds : echo '{\"host\":\"db.example.com\"}'"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "missing required 'env'"

  unstub vault
}

@test "Secrets field-mapping fails with malformed fields (missing name property)" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_FOO="bar"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "missing required 'name' property"

  unstub vault
}

@test "Secrets field-mapping fails with invalid env var name" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="password"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="MY-BAD-VAR"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/creds : echo '{\"password\":\"s3cret\"}'"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "invalid env var name"

  unstub vault
}

@test "Secrets field-mapping fails when field not found in secret" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/creds"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="nonexistent"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="SOME_VAR"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/creds : echo '{\"password\":\"s3cret\"}'"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "Field 'nonexistent' not found in secret"

  unstub vault
}

@test "Secrets field-mapping fails when vault fetch fails" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH="secret/ci/team/bad-path"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_NAME="password"
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_FIELDS_0_ENV="DATABASE_PASSWORD"

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0" \
    "kv get -address=https://vault_svr_url -field=data -format=json secret/ci/team/bad-path : exit 1"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "Failed to fetch secret from secret/ci/team/bad-path"

  unstub vault
}

@test "Secrets fails with empty path" {
  export BUILDKITE_PLUGIN_VAULT_SECRETS_SECRETS_0_PATH=""

  stub vault \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite/testpipe : exit 0" \
    "kv list -address=https://vault_svr_url -format=yaml data/buildkite : exit 0"

  run bash -c "$PWD/hooks/environment"

  assert_failure
  assert_output --partial "empty path"

  unstub vault
}
