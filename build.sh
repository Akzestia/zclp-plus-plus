cd build;
cmake -G Ninja -DBUILD_SERVER=ON -DBUILD_CLIENT=ON .. && ninja;
cd ..;
