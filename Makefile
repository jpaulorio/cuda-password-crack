output = password_crack
cpp_files = $(wildcard *.cpp)
cuda_files = $(wildcard *.cu)
cpp_objects = $(cpp_files:.cpp=.o)
cuda_objects = $(cuda_files:.cu=.o)
objects = $(cpp_objects) $(cuda_objects)

all: $(objects)
	nvcc -ccbin g++ -Wno-deprecated-gpu-targets -arch=sm_50 $(objects) -o password_crack

$(cpp_objects): %.o: %.cpp
	nvcc -ccbin g++ -Wno-deprecated-gpu-targets -x cu -m64 -arch=sm_50 -I. -dc $< -o $@

$(cuda_objects): %.o: %.cu
	nvcc -ccbin g++ --ptxas-options=-v -Wno-deprecated-gpu-targets -x cu -m64 -arch=sm_50 -I. -dc $< -o $@

run: all
	@./$(output)

clean:
	rm -f *.o $(output)