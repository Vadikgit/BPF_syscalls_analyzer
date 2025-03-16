#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <cstring>

int main()
{
	std::ofstream("file.bin").close();

	std::fstream file;
	file.open("file.bin", std::ios::binary | std::ios::out | std::ios::in);
	if (!file)
	{
		std::cerr << "Uh oh, SomeText.txt could not be opened for writing!" << std::endl;
		exit(1);
	}

	size_t NUMBER_OF_VALUES_IN_ITERATION = 10'000;
	size_t NUMBER_OF_ITERATIONS = 5'000'000'000 / 4 / NUMBER_OF_VALUES_IN_ITERATION;

	std::vector<size_t> fileposes;
	for (size_t i = 0; i < NUMBER_OF_ITERATIONS; i++)
	{
		fileposes.push_back(i);
	}

	std::random_shuffle(fileposes.begin(), fileposes.end());

	//	for (auto p : fileposes)
	//	std::cout << p << ' ';
	std::cout << '\n';

	std::vector<uint32_t> arr(NUMBER_OF_VALUES_IN_ITERATION, 0);
	for (size_t i = 0; i < NUMBER_OF_VALUES_IN_ITERATION; i++)
	{
		arr[i] = rand();
	}

	std::chrono::time_point<std::chrono::system_clock> t1, t2;

	std::vector<uint8_t> bytes;
	bytes.assign(NUMBER_OF_VALUES_IN_ITERATION * 4, 0);

	std::memcpy((void *)&(bytes[0]), (void *)&(arr[0]), arr.size() * sizeof(uint32_t));

	t1 = std::chrono::system_clock::now();
	file.seekp(0);
	for (size_t i = 0; i < NUMBER_OF_ITERATIONS; i++)
	{
		file.seekp(fileposes[i] * NUMBER_OF_VALUES_IN_ITERATION * 4);
		file.write((char *)&(bytes[0]), bytes.size());
	}
	file.sync();
	t2 = std::chrono::system_clock::now();

	std::chrono::microseconds dur = (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1));

	std::cout << "Write time: " << dur.count() << " mcs;\tSpeed: " << NUMBER_OF_VALUES_IN_ITERATION * NUMBER_OF_ITERATIONS * 4 / dur.count() << " Mb/s" << std::endl;

	/////////////////////////////////////////////////////

	std::vector<uint32_t> r_arr(NUMBER_OF_VALUES_IN_ITERATION, 0);
	std::vector<uint8_t> r_bytes;
	r_bytes.assign(NUMBER_OF_VALUES_IN_ITERATION * 4, 0);

	t1 = std::chrono::system_clock::now();
	file.seekp(0);
	for (size_t i = 0; i < NUMBER_OF_ITERATIONS; i++)
	{
		file.seekp(fileposes[i] * NUMBER_OF_VALUES_IN_ITERATION * 4);
		file.read((char *)&(r_bytes[0]), r_bytes.size());
	}
	file.sync();

	t2 = std::chrono::system_clock::now();

	std::memcpy((void *)&(r_arr[0]), (void *)&(r_bytes[0]), r_arr.size() * sizeof(uint32_t));

	dur = (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1));

	std::cout << "Read time: " << dur.count() << " mcs;\tSpeed: " << NUMBER_OF_VALUES_IN_ITERATION * NUMBER_OF_ITERATIONS * 4 / dur.count() << " Mb/s" << std::endl;

	std::fstream clear_file("file.bin", std::ios::out);
	clear_file.close();

	return 0;
}
