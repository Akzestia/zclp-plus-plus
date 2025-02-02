#!/bin/bash

EXCLUDED_TESTS=("server_async");

for file in tests/*.cpp; do
    if [[ -f "$file" ]]; then
        name=$(basename "$file" .cpp)

        if [[ " ${EXCLUDED_TESTS[@]} " =~ " ${name} " ]]; then
            echo "Skipping test: $name"
            continue
        fi

        test_file="tests/bin/${name}.test"
        echo "Generating test file: $test_file"

        clang++ -o $test_file $file -lgtest -lgtest_main -pthread;

        chmod +x "$test_file"
    fi
done

echo "Test generation complete."
