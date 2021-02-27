#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>

#define total_no_ascii_chars 95
#define max_encrypted_pwd_length 8

extern "C"
void ulong_to_char_array(unsigned long search_pos, char *output);

extern "C"
void runSerial(char *encrypted_password, unsigned long search_space_size, unsigned int pwd_mem_size);

extern "C"
unsigned long char_array_to_ulong(char *input, uint array_lenght);

void strcpy (char *origin, char *destination, unsigned int size) {
    for (int i=0; i < size; i++) {
        destination[i] = origin[i];
    }
}

void fill_with_zeros(char *array, unsigned int array_lenght) {
    for (int i=0; i < array_lenght; i++) {
        array[i] = 0;
    }
}

void ulong_to_char_array(unsigned long search_pos, char *output) {
    char pwd_candidate[max_encrypted_pwd_length];
    fill_with_zeros(pwd_candidate, max_encrypted_pwd_length);

    unsigned long integer_part = search_pos / total_no_ascii_chars;
    unsigned long remainder = search_pos % total_no_ascii_chars;
    unsigned int idx = 0;
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

    strcpy(pwd_candidate, output, max_encrypted_pwd_length);
}

unsigned long char_array_to_ulong(char *input, uint array_lenght) {
    unsigned long result = 0;
    for (int i=0; i < array_lenght && input[i] != 0; i++) {
        result += (input[i] - 32) * pow(total_no_ascii_chars, i);
    }
    return result;
}

unsigned long encrypt(unsigned long input, uint encryption_key) {
    unsigned long tmp_pwd = input * encryption_key;
    return tmp_pwd;
}

unsigned long crackPassword(char *encrypted_password, unsigned long search_space_size)
{
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

    unsigned long long_encrypted = char_array_to_ulong(encrypted_password, 7);

    for (unsigned long i = 0; i < search_space_size; i++)
    {
        for (unsigned long j = 0; j < sizeof(encryption_keys); j++)
        {
            uint key = encryption_keys[j];

            unsigned long tmp_encrypted = encrypt(i, key);

            if (long_encrypted == tmp_encrypted) {
                return i;
            }
        }
    }

    return 0;
}

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

void runSerial(char *encrypted_password, unsigned long search_space_size, unsigned int pwd_mem_size)
{
    printf("Running serial version...\n");

    start();

    unsigned long answer = crackPassword(encrypted_password, search_space_size);

    char *decrypted_password = (char *) malloc(pwd_mem_size);
    ulong_to_char_array(answer, decrypted_password);

    printf("Decrypted password: %s \n", decrypted_password);

    stop();
}