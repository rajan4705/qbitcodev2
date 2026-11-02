#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Vulnerability 1: Critical Stack Buffer Overflow (CWE-120 / CWE-787)
void process_user_input(const char *user_payload) {
    char stack_buffer[64];
    // Unsafe string copy without boundary check causes buffer overflow
    strcpy(stack_buffer, user_payload);
    printf("Processed input: %s\n", stack_buffer);
}

// Vulnerability 2: Critical Remote Command Injection (CWE-78)
int execute_system_query(const char *domain_name) {
    char command[256];
    // Dangerous format string concatenation into shell command
    snprintf(command, sizeof(command), "nslookup %s", domain_name);
    // Arbitrary command execution via untrusted shell invocation
    return system(command);
}

// Vulnerability 3: Use After Free (CWE-416)
char* allocate_and_free(const char *data) {
    char *buf = malloc(128);
    if (!buf) return NULL;
    strncpy(buf, data, 127);
    buf[127] = '\0';
    free(buf);
    // Returning and using pointer after it has been freed
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <payload>\n", argv[0]);
        return 1;
    }
    process_user_input(argv[1]);
    execute_system_query(argv[1]);
    char *ptr = allocate_and_free("test");
    printf("UAF output: %s\n", ptr);
    return 0;
}
