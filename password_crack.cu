////////////////////////////////////////////////////////////////////////////
//
// Copyright 1993-2015 NVIDIA Corporation.  All rights reserved.
//
// Please refer to the NVIDIA end user license agreement (EULA) associated
// with this source code for terms and conditions that govern your use of
// this software. Any use, reproduction, disclosure, or distribution of
// this software and related documentation outside the terms of the EULA
// is strictly prohibited.
//
////////////////////////////////////////////////////////////////////////////

/* Template project which demonstrates the basics on how to setup a project
* example application.
* Host code.
*/

// includes, system
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <dirent.h>

#include <cuda_runtime.h>

#include <helper_cuda.h>
#include <helper_functions.h> // helper functions for SDK examples

#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
#define total_no_ascii_chars 95
#define max_encrypted_pwd_length 8

extern "C"
void ulong_to_char_array(unsigned long search_pos, char *output);

extern "C"
void runSerial(unsigned long encrypted_password, unsigned long search_space_size, unsigned int pwd_mem_size);

extern "C"
unsigned long char_array_to_ulong(char *input, uint array_lenght);

static struct timeval tm1;

static inline void start()
{
    gettimeofday(&tm1, NULL);
}

static inline void stop()
{
    struct timeval tm2;
    gettimeofday(&tm2, NULL);

    unsigned long long t = 1000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec) / 1000;
    printf("Processing time: %llu (ms)\n", t);
}

inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true)
{
   if (code != cudaSuccess) 
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

void runParallel(int argc, char **argv,
    unsigned long encrypted_password, unsigned long search_space_size, unsigned int pwd_mem_size, uint key_list_size);

__device__ __forceinline__ unsigned long d_encrypt(unsigned long input, uint encryption_key) {
    unsigned long tmp_pwd = input * encryption_key;
    return tmp_pwd;
}

__device__ int g_found = 0;
__device__ unsigned long d_answer = 0;

__global__ void
crackPassword(unsigned long encrypted_password, unsigned long pageDim, unsigned long pageId)
{
    const unsigned long tidx = threadIdx.x;
    const unsigned long tidy = threadIdx.y;
    const unsigned long bid = blockIdx.x;
    const unsigned int num_threads = blockDim.x;
    const unsigned long global_tid = (pageId * gridDim.x * blockDim.x) + (bid * num_threads) + tidx;

    const uint encryption_keys[] = {
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
        179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
        353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
        419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 
        467, 479, 487, 491, 499, 503, 509, 521, 523, 541
    };
    uint key = encryption_keys[tidy];

    if (g_found) {
        return;
    }

    unsigned long tmp_encrypted = d_encrypt(global_tid, key);

    if (encrypted_password == tmp_encrypted) {
        d_answer = global_tid;
        g_found = 1;
    }
}

int main(int argc, char **argv)
{
    const unsigned int pwd_max_size = 32 + 1;
    const uint key_list_size = 90;
    
    char encrypted_password[pwd_max_size];
    printf("Enter the encrypted password:\n");
    scanf("%7s", encrypted_password);
    
    uint pwd_size = strlen(encrypted_password);
    
    unsigned int pwd_mem_size = (pwd_size + 1) * sizeof(char);
    unsigned long search_space_size = pow(total_no_ascii_chars, 5);
    printf("Search space size: %lu\n", search_space_size * key_list_size);

    unsigned long long_encrypted = char_array_to_ulong(encrypted_password, 7);

    runParallel(argc, argv,
        long_encrypted, search_space_size, pwd_mem_size, key_list_size);
    runSerial(long_encrypted, search_space_size, pwd_mem_size);

    exit(EXIT_SUCCESS);
}

void
runParallel(int argc, char **argv,
    unsigned long encrypted_password, unsigned long search_space_size, unsigned int pwd_mem_size, uint key_list_size)
{
    printf("Running parallel version...\n");

    // use command-line specified CUDA device, otherwise use device with highest Gflops/s
    findCudaDevice(argc, (const char **)argv);

    // setup execution parameters
    const uint num_threads_per_block =  10;
    uint num_blocks = 5000;
    unsigned long numberIterations = (search_space_size / (num_blocks * num_threads_per_block)) + 1;

    printf("Launching %lu iterations...\n", numberIterations);
    printf("Launching %d blocks per iteration...\n", num_blocks);
    printf("Launching %d threads per block...\n", num_threads_per_block * key_list_size);
    printf("Launching %d threads per iteration...\n", num_blocks * num_threads_per_block * key_list_size);
    printf("Launching %lu total threads...\n", num_blocks * num_threads_per_block * key_list_size * numberIterations);

    dim3 grid(num_blocks, 1, 1);
    dim3 threads(num_threads_per_block, key_list_size, 1);

    // allocate mem for the result on host side
    char *decrypted_password = (char *) malloc(pwd_mem_size);

    start();
    // execute the kernel
    for (uint i=0; i < numberIterations; i++) {
        crackPassword<<<grid, threads>>>(encrypted_password, numberIterations, i);

        // check if kernel execution generated an error
        getLastCudaError("Kernel execution failed");
        gpuErrchk(cudaPeekAtLastError());
        gpuErrchk(cudaDeviceSynchronize());

        // copy result from device to host
        typeof(d_answer) answer;
        checkCudaErrors(cudaMemcpyFromSymbol(&answer, d_answer, sizeof(answer), 0, cudaMemcpyDeviceToHost));
        
        if (answer != 0) {            
            ulong_to_char_array(answer, decrypted_password);
            printf("Decrypted password: %s \n", decrypted_password);
            break;
        }
    }
    stop();

    // cleanup memory
    free(decrypted_password);
}
