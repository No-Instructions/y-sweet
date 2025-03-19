#!/usr/bin/env bash
# wrapper that sources an environment file and executes any arguments
export PATH=$PWD:$PATH
set -a # force export
. .auth.env
set +a # turn off force export
eval "$@"
