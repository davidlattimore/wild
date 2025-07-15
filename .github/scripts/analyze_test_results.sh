#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_CMD="python3"

ALL_TESTS_OUTPUT="$(pwd)/all_tests_output.txt"
FAILED_TESTS="$(pwd)/failed_tests.txt"
PASSED_TESTS="$(pwd)/passed_tests.txt"

${PYTHON_CMD} -c "
import re
import sys
import os

with open('${ALL_TESTS_OUTPUT}', 'r') as f:
    content = f.read()

failed_tests = []
passed_tests = []

for line in content.split('\n'):
    if 'external_tests::mold_tests::exec_mold_tests::' in line and ('FAILED' in line or '... ok' in line):
        match = re.search(r'external_tests::mold_tests::exec_mold_tests::(.+?)\s+\.\.\.\s+(FAILED|ok)', line)
        if match:
            test_name = match.group(1)
            status = match.group(2)
            
            if status == 'FAILED':
                failed_tests.append(test_name)
            elif status == 'ok':
                passed_tests.append(test_name)

with open('${FAILED_TESTS}', 'w') as f:
    for test in failed_tests:
        f.write(test + '\n')

with open('${PASSED_TESTS}', 'w') as f:
    for test in passed_tests:
        f.write(test + '\n')

print(f'\\nFound {len(failed_tests)} failed tests and {len(passed_tests)} passed tests')
"
