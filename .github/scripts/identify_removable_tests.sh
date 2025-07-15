#!/bin/bash

set -e

PASSED_TESTS="$(pwd)/passed_tests.txt"
CURRENT_SKIP_LIST="$(pwd)/current_skip_list.txt"
REMOVABLE_TESTS="$(pwd)/removable_tests.txt"

while IFS= read -r skip_test; do
    while IFS= read -r passed_test; do
        if [[ "${passed_test}"* == "${skip_test}_sh" ]]; then
            echo "${skip_test}" >> "${REMOVABLE_TESTS}"
            break
        fi
    done < "${PASSED_TESTS}"
done < "${CURRENT_SKIP_LIST}"

if [[ -f "${REMOVABLE_TESTS}" && -s "${REMOVABLE_TESTS}" ]]; then
    echo "✅ Tests that can be removed from skip list:"
    cat "${REMOVABLE_TESTS}"
    echo ""
    echo "Total removable tests: $(wc -l < "${REMOVABLE_TESTS}")"
else
    echo "No tests can be removed from the skip list at this time."
fi
