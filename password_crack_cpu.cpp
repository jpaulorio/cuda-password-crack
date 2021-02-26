#define total_no_ascii_chars 95
#define max_encrypted_pwd_length 8

extern "C"
void ulong_to_char_array(unsigned long search_pos, char *output);

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