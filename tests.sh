#!/bin/bash

EXCLUDED_TESTS=("server_async")
ICyan='\033[0;96m'
IRed='\033[0;91m'
IGreen='\033[0;92m'
ColorReset='\033[0m'

select_single_test=false
select_multiple_tests=false
selected_tests=()

if [[ "$#" -gt 1 ]]; then
    echo -e "${IRed}Error: You can only use one flag option at a time.${ColorReset}"
    exit 1
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo -e "${ICyan}Usage: ./test.sh [OPTION]${ColorReset}"
    echo -e "Options:"
    echo -e "  -s              Select a single test to compile"
    echo -e "  -x              Select multiple tests to compile"
    echo -e "  -h, --help      Display this help message"
    echo -e "${ICyan}Example:${ColorReset}"
    echo -e "  ./test.sh -s      # Select and compile a single test"
    echo -e "  ./test.sh -x      # Select and compile multiple tests"
    echo -e "  ./test.sh         # Compile all tests"
    exit 0
fi

if [[ "$1" == "-s" ]]; then
    select_single_test=true
    echo -e "${ICyan}Select a test to compile (single selection):${ColorReset}"
elif [[ "$1" == "-x" ]]; then
    select_multiple_tests=true
    echo -e "${ICyan}Select tests to compile (multiple selection):${ColorReset}"
fi

test_files=()
for file in tests/*.cpp; do
    if [[ -f "$file" ]]; then
        name=$(basename "$file" .cpp)

        if [[ " ${EXCLUDED_TESTS[@]} " =~ " ${name} " ]]; then
            continue
        fi

        test_files+=("$name")
    fi
done

if [[ "$select_single_test" == false && "$select_multiple_tests" == false ]]; then
    for file in tests/*.cpp; do
        if [[ -f "$file" ]]; then
            name=$(basename "$file" .cpp)

            if [[ " ${EXCLUDED_TESTS[@]} " =~ " ${name} " ]]; then
                echo -e "${IRed}Skipping test: $name${ColorReset}"
                continue
            fi

            test_file="tests/bin/${name}.test"
            echo -e "${IGreen}Generating test file: $test_file${ColorReset}"

            clang++ -o $test_file $file -lgtest -lgtest_main -pthread -lcrypto

            chmod +x "$test_file"
        fi
    done
else
    if [[ "$select_single_test" == true ]]; then
        select selected_test in "${test_files[@]}"; do
            if [[ -n "$selected_test" ]]; then
                echo -e "${IGreen}You selected: $selected_test${ColorReset}"
                test_file="tests/bin/${selected_test}.test"
                clang++ -o $test_file "tests/${selected_test}.cpp" -lgtest -lgtest_main -pthread -lcrypto
                chmod +x "$test_file"
                selected_tests+=("$test_file")
                break
            else
                echo -e "${IRed}Invalid selection. Please choose a valid test.${ColorReset}"
            fi
        done
    fi

    if [[ "$select_multiple_tests" == true ]]; then
        echo -e "${ICyan}Select tests to compile (space-separated list of numbers, then press Enter):${ColorReset}"

        for i in "${!test_files[@]}"; do
            echo "$((i+1)): ${test_files[$i]}"
        done

        read -p "Enter the test numbers to compile (e.g. '1 2 6'): " user_input

        selected_tests=()
        selected_tests_numbers=($user_input)

        for test_num in "${selected_tests_numbers[@]}"; do
            if [[ "$test_num" -ge 1 && "$test_num" -le ${#test_files[@]} ]]; then
                test="${test_files[$((test_num-1))]}"
                test_file="tests/bin/${test}.test"
                echo -e "${IGreen}Compiling test: $test_file${ColorReset}"
                clang++ -o $test_file "tests/${test}.cpp" -lgtest -lgtest_main -pthread -lcrypto
                chmod +x "$test_file"
                selected_tests+=("$test_file")
            else
                echo -e "${IRed}Invalid selection: $test_num${ColorReset}"
            fi
        done
    fi
fi

echo ""

read -r -p $'\e[0;96mTest generation complete. Run Tests [Y/n]?\e[0m' user_input

user_input=${user_input,,}
if [[ "$user_input" =~ ^(no|n)$ ]]; then
    exit 0
elif [[ "$user_input" =~ ^(yes|y|)$ ]]; then
    if [[ ${#selected_tests[@]} -gt 0 ]]; then
        clear && clear
        exec "./run_test.sh" "${selected_tests[@]}"
    else
        clear && clear
        exec "./run_test.sh"
    fi
else
    exit 0
fi
