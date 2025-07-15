#!/bin/bash

set -e

FAILED_TESTS="$(pwd)/failed_tests.txt"
CURRENT_SKIP_LIST="$(pwd)/current_skip_list.txt"
REGRESSIONS="$(pwd)/regressions.txt"

# Find tests that are not in skip list but failed (these are regressions)
while IFS= read -r failed_test; do
    # Check if any skip list entry is a substring of this failed test
    is_skipped=false
    failed_test_name=$(echo "${failed_test}" | sed 's/.*test_suites_mold_test_//')
    while IFS= read -r skip_test; do
        # Replace '+', '.' and '-' with '_' in skip_test to align with rstest behavior
        skip_test_converted="${skip_test//+/_}"
        skip_test_converted="${skip_test_converted//./_}"
        skip_test_converted="${skip_test_converted//-/_}"
        
        if [[ "${skip_test_converted}_sh" == "${failed_test_name}"* ]]; then
            is_skipped=true
            break
        fi
    done < "${CURRENT_SKIP_LIST}"

    if [[ "${is_skipped}" == "false" ]]; then
        echo "${failed_test}" >> "${REGRESSIONS}"
    fi
done < "${FAILED_TESTS}"

if [[ -f "${REGRESSIONS}" && -s "${REGRESSIONS}" ]]; then
    sort -u "${REGRESSIONS}" -o "${REGRESSIONS}"
fi

if [[ -f "${REGRESSIONS}" && -s "${REGRESSIONS}" ]]; then
    echo "REGRESSION DETECTED!"
    echo "The following tests are failing but not in the skip list:"
    cat "${REGRESSIONS}"
    echo "Please fix these tests or add them to the skip list."
    exit 1
fi

echo "No regressions detected."
