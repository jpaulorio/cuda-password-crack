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

////////////////////////////////////////////////////////////////////////////////
// declaration, forward
void runTest(int argc, char **argv);

__device__ int d_strcmp (char *s1, char *s2) {
    char *tmp_s1 = s1;
    char *tmp_s2 = s2;
    for(; *tmp_s1 == *tmp_s2; ++tmp_s1, ++tmp_s2) {
        if(*tmp_s1 == 0)
            return 0;
    }
    return *(unsigned char *)tmp_s1 < *(unsigned char *)tmp_s2 ? -1 : 1;
}

__device__ void d_strcpy (char *origin, char *destination) {
    char *tmp = origin;
    int idx = 0;
    for (; *tmp != 0; ++idx, ++tmp) {
        destination[idx] = *tmp;
    }
    destination[idx] = 0;
}

__device__ void d_encrypt(char *uncrypted, char *encryption_key, int key_length, char *encrypted) {
    char *tmp_uncrypted = uncrypted;
    char *tmp_encrypted = encrypted;
    for (uint i = 0; *tmp_uncrypted != 0; ++i, ++tmp_uncrypted, ++tmp_encrypted) {
        if (*tmp_uncrypted != 0) {
            uint key_index = i % key_length;
            *tmp_encrypted = (*tmp_uncrypted + encryption_key[key_index]) % 128;
        } else {
            *tmp_encrypted = 0;
        }
    }
}

__device__ void fill_with_zeros(char *array) {
    int array_lenght = sizeof(array);
    for (int i=0; i < array_lenght - 1; i++) {
        array[i] = 0;
    }
    array[array_lenght - 1] = 0;
}

__device__ void d_ulong_to_char_array(unsigned long search_pos, unsigned long search_space_size, char *output) {
    const uint total_no_ascii_chars = 128;
    char pwd_candidate[7];
    fill_with_zeros(pwd_candidate);

    unsigned int integer_part = search_pos / total_no_ascii_chars;
    unsigned int remainder = search_pos % total_no_ascii_chars;
    uint idx = 0;
    pwd_candidate[idx] = remainder;
    pwd_candidate[idx + 1] = integer_part;
    printf("integer: %lu\n", integer_part);
    printf("remainder: %lu\n", remainder);
    while (integer_part > 0) {
        pwd_candidate[idx] = remainder;
        pwd_candidate[idx + 1] = integer_part;
        integer_part = integer_part / total_no_ascii_chars;
        remainder = integer_part % total_no_ascii_chars;
        printf("integer: %lu\n", integer_part);
        printf("remainder: %lu\n", remainder);
        idx++;
    }

    printf("candidate: %s\n", pwd_candidate);

    d_strcpy(pwd_candidate, output);
}

__global__ void
crackPassword(
    int g_encrypted_password_length, char *g_encrypted_password, char *g_decrypted_password,
    int g_encryption_key_length, char *g_encryption_key,
    unsigned long g_search_space_size, int g_found)
{
    __shared__ char s_encrypted_password[7];
    __shared__ char s_encryption_key[4];
    char temp_password[7];
    char temp_encrypted_password[7];
    
    const unsigned int tid = threadIdx.x;
    const unsigned int bid = blockIdx.x;
    const unsigned int num_threads = blockDim.x;
    const unsigned long l_search_space_size = g_search_space_size;
    const unsigned long start_search = 0;
    const unsigned long end_search = l_search_space_size;
    const int key_length = g_encryption_key_length;
    unsigned long search_pos = start_search;
    unsigned int i_found = g_found;

    if (tid == 0) {
        d_strcpy(g_encrypted_password, s_encrypted_password);
        d_strcpy(g_encryption_key, s_encryption_key);
    }
    __syncthreads();

    while (!g_found) {
        d_ulong_to_char_array(search_pos, l_search_space_size, temp_password);
        printf("temp pwd: %s\n", temp_password);
        d_encrypt(temp_password, s_encryption_key, key_length, temp_encrypted_password);
        printf("temp enc pwd: %s\n", temp_encrypted_password);
        i_found = d_strcmp(temp_encrypted_password, s_encrypted_password) == 0;
        printf("i found: %d\n", i_found);
        if (i_found) {
            g_found = 1;
        }
        search_pos++;
    }

    if (i_found) {
        printf("found!!!\n");
        d_strcpy(temp_password, g_decrypted_password);
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
    bool bTestResult = true;

    printf("%s Starting...\n\n", argv[0]);

    // use command-line specified CUDA device, otherwise use device with highest Gflops/s
    int devID = findCudaDevice(argc, (const char **)argv);

    
    unsigned int num_threads = 1;
    unsigned int pwd_max_size = 32 + 1;
    unsigned int key_max_size = 32 + 1;
    
    char encrypted_password[pwd_max_size];
    char encryption_key[key_max_size];
    printf("Enter the encrypted password:\n");
    scanf("%32s", encrypted_password);
    printf("Enter the encryption key:\n");
    scanf("%32s", encryption_key);
    
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

    // setup execution parameters
    dim3  grid(1, 1, 1);
    dim3  threads(num_threads, 1, 1);

    cudaEventRecord(start);
    // execute the kernel
    crackPassword<<<grid, threads>>>(pwd_size, d_encrypted_password, d_decrypted_password, key_size, d_encryption_key, search_space_size, 0);
    cudaEventRecord(stop);

    // check if kernel execution generated and error
    getLastCudaError("Kernel execution failed");

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
