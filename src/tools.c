#include "tools.h"
#include <stdio.h>

void hexprint(unsigned char *buffer, int buffer_len)
{
    int i;
    for (i = 0; i < buffer_len; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
}
