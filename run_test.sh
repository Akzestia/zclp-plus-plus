#!/bin/bash

if [[ $# -gt 0 ]]; then
    test_files=("$@")
else
    test_files=(tests/bin/*.test)
fi

if [[ ${#test_files[@]} -eq 0 ]]; then
    echo "No test files found in tests/bin/"
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "Available tests:"
    for i in "${!test_files[@]}"; do
        echo "[$i] $(basename "${test_files[$i]%.*}")"
    done

    echo "Enter the test number to run (or type 'a' to run all):"
    read -r user_input

    if [ "$user_input" == "a" ] || [ "$user_input" == "" ]; then
        for file in "${test_files[@]}"; do
            echo "Running test: $file"
            "$file"
        done
    elif [[ "$user_input" =~ ^[0-9]+$ && $user_input -ge 0 && $user_input -lt ${#test_files[@]} ]]; then
        echo "Running test: ${test_files[$user_input]}"
        "${test_files[$user_input]}"
    else
        echo "Invalid selection. Please enter a valid test number or 'a' to run all tests."
        exit 1
    fi
else
    for file in "${test_files[@]}"; do
        echo "Running test: $file"
        "$file"
    done
fi

echo "Test execution complete."
