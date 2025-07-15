#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_CMD="python3"

SKIP_LIST_FILE="wild/tests/external_tests/mold_skip_tests.toml"
CURRENT_SKIP_LIST="$(pwd)/current_skip_list.txt"

${PYTHON_CMD} -c "
import toml
import sys
try:
    with open('${SKIP_LIST_FILE}', 'r') as f:
        config = toml.load(f)
    
    all_skipped = []
    for group_name, group_data in config.get('skipped_groups', {}).items():
        all_skipped.extend(group_data.get('tests', []))
    
    for test in all_skipped:
        test_name = test
        if test_name.endswith('.sh'):
            test_name = test_name[:-3]
        # Convert special characters to match rstest behavior
        converted_name = test_name.replace('+', '_').replace('.', '_').replace('-', '_')
        print(converted_name)
except Exception as e:
    print(f'Error parsing TOML: {e}', file=sys.stderr)
    sys.exit(1)
" > "${CURRENT_SKIP_LIST}"

echo "Loaded current skip list from ${SKIP_LIST_FILE} to ${CURRENT_SKIP_LIST}"
