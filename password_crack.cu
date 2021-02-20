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

__device__ void d_encrypt(char *uncrypted, char *encryption_key, int key_length, char *encrypted) {
    fill_with_zeros(encrypted, 7);
    for (int i = 0; i < 7; i++) {
        int key_index = i % key_length;
        if (uncrypted[i] > 0) {
            encrypted[i] = (uncrypted[i] + encryption_key[key_index]) % 128;
        }
    }
}

__device__ void d_ulong_to_char_array(unsigned long search_pos, char *output) {
    const uint total_no_ascii_chars = 128;
    char pwd_candidate[7];
    fill_with_zeros(pwd_candidate, 7);

    unsigned long integer_part = search_pos / total_no_ascii_chars;
    unsigned long remainder = search_pos % total_no_ascii_chars;
    uint idx = 0;
    pwd_candidate[idx] = remainder;
    pwd_candidate[idx + 1] = integer_part;

    while (integer_part > 0) {
        idx++;
        remainder = integer_part % total_no_ascii_chars;
        integer_part = integer_part / total_no_ascii_chars;
        pwd_candidate[idx] = remainder;
        pwd_candidate[idx + 1] = integer_part;
    }

    d_strcpy(pwd_candidate, output);
}

__global__ void
crackPassword(
    int g_encrypted_password_length, char *g_encrypted_password, char *g_decrypted_password,
    int g_encryption_key_length, char *g_encryption_key,
    unsigned long g_search_space_size, int g_found)
{
    __shared__ char s_encrypted_password[7];
    char s_encryption_key[4];
    char temp_password[7];
    char temp_encrypted_password[7];
    
    const unsigned int tid = threadIdx.x;
    const unsigned int bid = blockIdx.x;
    const unsigned int num_threads = blockDim.x;
    const unsigned int global_tid = bid * num_threads + tid;
    const unsigned int global_num_threads = gridDim.x * blockDim.x;

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
    if (start_search > l_search_space_size) {
        return;
    }
    if (end_search > l_search_space_size) {
        end_search = l_search_space_size;
    }
    const int key_length = g_encryption_key_length;
    unsigned long search_pos = start_search;
    
    fill_with_zeros(s_encryption_key, 4);
    d_strcpy(g_encryption_key, s_encryption_key);

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
        d_ulong_to_char_array(search_pos, temp_password);

        d_encrypt(temp_password, s_encryption_key, key_length, temp_encrypted_password);

        // if (search_pos == 12583009) {
        //     for (int i =0; i < 7; i++)
        //         printf("DEBUG: tmp pwd %d: %d\n", i, temp_password[i]);
        //     for (int i =0; i < 7; i++)
        //         printf("DEBUG: enc pwd %d: %d\n", i, s_encrypted_password[i]);
        //     for (int i =0; i < 7; i++)
        //         printf("DEBUG: tmp enc pwd %d: %d\n", i, temp_encrypted_password[i]);
        //     printf("COMP: %d\n", d_strcmp(temp_encrypted_password, s_encrypted_password));
        // }

        if (d_strcmp(temp_encrypted_password, s_encrypted_password) == 0) {
            d_strcpy(temp_password, g_decrypted_password);
            // printf("Thread %d found it! [%s] Block id:Thread is - %d:%d\n", global_tid, temp_password, bid, tid);
            // printf("Thread %d start:end:current - %lu:%lu:%lu\n", global_tid, start_search, end_search, search_pos);
            g_found = 1;
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
    printf("Enter the encryption key:\n");
    scanf("%4s", encryption_key);
    
    uint pwd_size = strlen(encrypted_password);
    uint key_size = strlen(encryption_key);
    
    unsigned int pwd_mem_size = (pwd_size + 1) * sizeof(char);
    unsigned int key_mem_size = (key_size + 1) * sizeof(char);
    unsigned long search_space_size = pow(128, pwd_size);
    printf("Search space size: %lu\n", search_space_size);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    char *d_encrypted_password, *d_decrypted_password, *d_encryption_key;
    checkCudaErrors(cudaMalloc((void **) &d_encrypted_password, pwd_mem_size));
    checkCudaErrors(cudaMalloc((void **) &d_encryption_key, key_mem_size));
    //output
    checkCudaErrors(cudaMalloc((void **) &d_decrypted_password, pwd_mem_size));
    
    checkCudaErrors(cudaMemcpy(d_encrypted_password, encrypted_password, pwd_mem_size, cudaMemcpyHostToDevice));
    checkCudaErrors(cudaMemcpy(d_encryption_key, encryption_key, key_mem_size, cudaMemcpyHostToDevice));
    cudaStreamQuery(0);

    // setup execution parameters
    unsigned int num_threads = 512;
    unsigned int num_blocks = pow(2,21);
    dim3  grid(num_blocks, 1, 1);
    dim3  threads(num_threads, 1, 1);

    cudaEventRecord(start);
    // execute the kernel
    crackPassword<<<grid, threads>>>(pwd_size, d_encrypted_password, d_decrypted_password, key_size, d_encryption_key, search_space_size, 0);
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
    checkCudaErrors(cudaFree(d_encryption_key));
    checkCudaErrors(cudaFree(d_decrypted_password));

    exit(EXIT_SUCCESS);
}
