#!/bin/bash
for file in tests/bin/*.test; do
    if [[ -f "$file" ]]; then
        echo "Running test: $file"
        ./$file
    fi
done

echo "Test execution complete."
