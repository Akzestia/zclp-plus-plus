#!/bin/bash

ICyan='\033[0;96m'
IRed='\033[0;91m'
IGreen='\033[0;92m'
ColorReset='\033[0m'

# header_protection
EXCLUDED_TESTS=("server_async header_protection")

select_single_test=false
select_multiple_tests=false
selected_tests=()

mkdir -p tests/build
cd tests/build

build_selected_tests() {
    local test_names=("$@")
    local cmake_options=()

    for test in "${test_files[@]}"; do
        cmake_options+=("-DBUILD_${test^^}=OFF")
    done

    for test in "${test_names[@]}"; do
        echo -e "${IGreen}Building test: $test${ColorReset}"
        cmake_options+=("-DBUILD_${test^^}=ON")
    done

    cmake .. "${cmake_options[@]}"

    if [ $? -eq 0 ]; then
        cmake --build .
    else
        echo -e "${IRed}CMake configuration failed${ColorReset}"
        exit 1
    fi
}

if [[ "$#" -gt 1 ]]; then
    echo -e "${IRed}Error: You can only use one flag option at a time.${ColorReset}"
    exit 1
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo -e "${ICyan}Usage: ./test.sh [OPTION]${ColorReset}"
    echo -e "Options:"
    echo -e "  -s              Select a single test to compile"
    echo -e "  -x              Select multiple tests to compile"
    echo -e "  --no-confirm    Automatically run the tests without confirmation"
    echo -e "  -h, --help      Display this help message"
    echo -e "${ICyan}Example:${ColorReset}"
    echo -e "  ./test.sh -s      # Select and compile a single test"
    echo -e "  ./test.sh -x      # Select and compile multiple tests"
    echo -e "  ./test.sh         # Compile all tests"
    echo -e "  ./test.sh --no-confirm   # Automatically run the tests"
    exit 0
fi

test_files=($(grep "BUILD_.*_FRAME\|BUILD_.*_HEADER\|BUILD_.*_PROTECTION\|BUILD_.*_RESET\|BUILD_.*_NEGOTIATION\|BUILD_VL_INTEGER" ../CMakeLists.txt | sed 's/option(BUILD_\(.*\) "Build.*/\1/' | tr '[:upper:]' '[:lower:]'))

EXCLUDED_TESTS=($(echo "${EXCLUDED_TESTS[@]}" | tr '[:upper:]' '[:lower:]'))

for excluded in "${EXCLUDED_TESTS[@]}"; do
    for i in "${!test_files[@]}"; do
        test_name_lower=$(echo "${test_files[$i]}" | tr '[:upper:]' '[:lower:]')
        if [[ "$test_name_lower" == "$excluded" ]]; then
            unset test_files[$i]
        fi
    done
done

test_files=("${test_files[@]}")

if [[ "$1" == "-s" ]]; then
    select_single_test=true
    echo -e "${ICyan}Select a test to compile (single selection):${ColorReset}"
    select selected_test in "${test_files[@]}"; do
        if [[ -n "$selected_test" ]]; then
            echo -e "${IGreen}You selected: $selected_test${ColorReset}"
            selected_tests+=("$selected_test")
            break
        else
            echo -e "${IRed}Invalid selection. Please choose a valid test.${ColorReset}"
        fi
    done
elif [[ "$1" == "-x" ]]; then
    select_multiple_tests=true
    echo -e "${ICyan}Select tests to compile (multiple selection):${ColorReset}"
    for i in "${!test_files[@]}"; do
        echo "$((i+1)): ${test_files[$i]}"
    done

    read -p "Enter the test numbers to compile (e.g. '1 2 6'): " user_input
    selected_tests_numbers=($user_input)

    for test_num in "${selected_tests_numbers[@]}"; do
        if [[ "$test_num" -ge 1 && "$test_num" -le ${#test_files[@]} ]]; then
            selected_tests+=("${test_files[$((test_num-1))]}")
        else
            echo -e "${IRed}Invalid selection: $test_num${ColorReset}"
        fi
    done
else
    selected_tests=("${test_files[@]}")
fi

if [[ ${#selected_tests[@]} -gt 0 ]]; then
    build_selected_tests "${selected_tests[@]}"
else
    echo -e "${IRed}No tests selected for building.${ColorReset}"
    exit 1
fi

cd ../..
if [[ "$1" == "--no-confirm" ]]; then
    clear && clear
    test_paths=()
    for test in "${selected_tests[@]}"; do
        test_paths+=("tests/bin/$test")
    done

    res=$("./run_test.sh" "${test_paths[@]}");

    if echo "$res" | grep "FAILED"; then
        echo -e "${IRed}Tests failed.${ColorReset}"
        exit 1
    else
        echo -e "${IGreen}Tests passed.${ColorReset}"
    fi

else
    echo ""
    read -r -p $'\e[0;96mBuild complete. Run Tests [Y/n]?\e[0m' user_input

    user_input=${user_input,,}
    if [[ "$user_input" =~ ^(no|n)$ ]]; then
        exit 0
    elif [[ "$user_input" =~ ^(yes|y|)$ ]]; then
        if [[ ${#selected_tests[@]} -gt 0 ]]; then
            clear && clear
            test_paths=()
            for test in "${selected_tests[@]}"; do
                test_paths+=("tests/bin/$test")
            done
            "./run_test.sh" "${test_paths[@]}";
        else
            clear && clear
            exec "./run_test.sh"
        fi
    else
        exit 0
    fi
fi
