#!/bin/bash

set -euxo pipefail

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CMD="${1:-test}"
if ! which docker ; then
    echo 'Docker is missing!' >&2
    exit 1
fi
if ! which docker-compose ; then
    echo 'Docker-Compose is missing!' >&2
    exit 1
fi
if [[ "$CMD" =~ [^a-zA-Z0-9] ]]; then
    echo "Invalid Command: ${CMD}" >&2
    exit 1
fi
cd "${BASEDIR}"
source "${BASEDIR}/ci/${CMD}.sh" "${@:2}"

