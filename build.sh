clang++ server-async-test.cpp -o tests/async.test;
cd build;
cmake -G Ninja -DBUILD_SERVER=ON -DBUILD_CLIENT=ON .. && ninja;
cd ..;
