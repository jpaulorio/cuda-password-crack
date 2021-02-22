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

inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true)
{
   if (code != cudaSuccess) 
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}
////////////////////////////////////////////////////////////////////////////////
// declaration, forward
void runTest(int argc, char **argv);

__device__ void fill_with_zeros(char *array, uint array_lenght) {
    for (int i=0; i < array_lenght; i++) {
        array[i] = 0;
    }
}

__device__ int d_strcmp (char *s1, char *s2) {
    for(int i=0; i < 7; i++) {
        if(s1[i] != s2[i])
            return 1;
    }
    return 0;
}

__device__ void d_strcpy (char *origin, char *destination) {
    for (int i=0; i < 7; i++) {
        destination[i] = origin[i];
    }
}

__device__ void d_ulong_to_char_array(unsigned long search_pos, char *output) {
    char pwd_candidate[256];
    fill_with_zeros(pwd_candidate, 256);

    unsigned long integer_part = search_pos / total_no_ascii_chars;
    unsigned long remainder = search_pos % total_no_ascii_chars;
    uint idx = 0;
    pwd_candidate[idx] = remainder + 32;
    pwd_candidate[idx + 1] = integer_part + 32;

    while (integer_part > 0) {
        idx++;
        remainder = integer_part % total_no_ascii_chars;
        integer_part = integer_part / total_no_ascii_chars;
        pwd_candidate[idx] = remainder + 32;
        pwd_candidate[idx + 1] = integer_part + 32;
    }
    pwd_candidate[idx + 1] = 0;

    d_strcpy(pwd_candidate, output);
}

__device__ void d_encrypt(uint input, uint encryption_key, char *encrypted) {
    fill_with_zeros(encrypted, 256);
    ulong tmp_pwd = input * encryption_key;
    d_ulong_to_char_array(tmp_pwd, encrypted);
}

__device__ int g_found = 0;

__global__ void
crackPassword(
    int g_encrypted_password_length, char *g_encrypted_password, char *g_decrypted_password,
    unsigned long g_search_space_size)
{
    __shared__ char s_encrypted_password[7];

    char temp_password[7];
    char temp_encrypted_password[256];
    
    const unsigned int tid = threadIdx.x;
    const unsigned int bid = blockIdx.x;
    const unsigned int num_threads = blockDim.x;
    const unsigned int global_tid = bid * num_threads + tid;
    const unsigned int global_num_threads = gridDim.x * blockDim.x;
    uint key_list_size = 90;
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

    const unsigned long l_search_space_size = g_search_space_size;
    unsigned long chunk_size = l_search_space_size / global_num_threads;

    if (chunk_size == 0) {
        chunk_size = l_search_space_size / num_threads;

        if (chunk_size == 0) {
            chunk_size = l_search_space_size;
        }
    }

    const unsigned long start_search = global_tid * chunk_size;
    unsigned long end_search = start_search + chunk_size;
    if (start_search >= l_search_space_size) {
        return;
    }
    if (end_search > l_search_space_size) {
        end_search = l_search_space_size;
    }
    unsigned long search_pos = start_search;

    if (tid == 0) {
        fill_with_zeros(s_encrypted_password, 7);
        d_strcpy(g_encrypted_password, s_encrypted_password);

        if (bid == 0) {
            printf("Global num threads: %d\n", global_num_threads);
            printf("Chunk size: %lu\n", chunk_size);
        }
    }
    __syncthreads();

    while (!g_found && search_pos < end_search) {
        uint key_search_pos = 0;        

        while (!g_found && key_search_pos < key_list_size) {
            uint key = encryption_keys[key_search_pos];

            d_encrypt(search_pos, key, temp_encrypted_password);

            if (d_strcmp(temp_encrypted_password, s_encrypted_password) == 0) {
                d_ulong_to_char_array(search_pos, temp_password);
                d_strcpy(temp_password, g_decrypted_password);
                printf("Password was found by thread %d!\nDetails: start|end|current - %lu:%lu:%lu\n",
                    global_tid, start_search, end_search, search_pos);
                g_found = 1;
            }
            key_search_pos++;
        }
        search_pos++;
    }
}

int
main(int argc, char **argv)
{
    runTest(argc, argv);
}

void
runTest(int argc, char **argv)
{
    printf("%s Starting...\n\n", argv[0]);

    // use command-line specified CUDA device, otherwise use device with highest Gflops/s
    int devID = findCudaDevice(argc, (const char **)argv);

    unsigned int pwd_max_size = 32 + 1;
    unsigned int key_max_size = 32 + 1;
    
    char encrypted_password[pwd_max_size];
    char encryption_key[key_max_size];
    printf("Enter the encrypted password:\n");
    scanf("%6s", encrypted_password);
    
    uint pwd_size = strlen(encrypted_password);
    uint key_size = strlen(encryption_key);
    
    unsigned int pwd_mem_size = (pwd_size + 1) * sizeof(char);
    unsigned long search_space_size = pow(total_no_ascii_chars, 5);
    printf("Search space size: %lu\n", search_space_size);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    char *d_encrypted_password, *d_decrypted_password;
    checkCudaErrors(cudaMalloc((void **) &d_encrypted_password, pwd_mem_size));
    //output
    checkCudaErrors(cudaMalloc((void **) &d_decrypted_password, pwd_mem_size));
    
    checkCudaErrors(cudaMemcpy(d_encrypted_password, encrypted_password, pwd_mem_size, cudaMemcpyHostToDevice));
    cudaStreamQuery(0);

    // setup execution parameters
    unsigned int num_threads = 512;
    unsigned int num_blocks = 1;
    unsigned long max_num_threads = pow(2,21);
    while (search_space_size > num_blocks * num_threads && num_blocks * num_threads < max_num_threads) {
        num_blocks++;
    }
    printf("Launching %d threads...\n", num_blocks * num_threads);
    // unsigned int num_blocks = pow(2,21);
    dim3  grid(num_blocks, 1, 1);
    dim3  threads(num_threads, 1, 1);

    cudaEventRecord(start);
    // execute the kernel
    crackPassword<<<grid, threads>>>(pwd_size, d_encrypted_password, d_decrypted_password, search_space_size);
    cudaStreamQuery(0);
    cudaEventRecord(stop);

    // check if kernel execution generated and error
    getLastCudaError("Kernel execution failed");
    gpuErrchk(cudaPeekAtLastError());
    gpuErrchk(cudaDeviceSynchronize());

    // allocate mem for the result on host side
    char *decrypted_password = (char *) malloc(pwd_mem_size);
    // copy result from device to host
    checkCudaErrors(cudaMemcpy(decrypted_password, d_decrypted_password, pwd_mem_size, cudaMemcpyDeviceToHost));
    
    cudaEventSynchronize(stop);
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);

    printf("Decrypted password: %s \n", decrypted_password);

    printf("Processing time: %f (ms)\n", milliseconds);

    // cleanup memory
    free(decrypted_password);
    checkCudaErrors(cudaFree(d_encrypted_password));
    checkCudaErrors(cudaFree(d_decrypted_password));

    exit(EXIT_SUCCESS);
}
