#include "nqp_io.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char **argv) {

    // int fd = 0;
    // ssize_t bytes_read = 0;
    int read_bytes = 400;
    unsigned char buffer[read_bytes];
    // int exit_code = EXIT_SUCCESS;
    nqp_error err = nqp_mount(argv[1], NQP_FS_EXFAT);
    (void)argc;
    (void)err;
    int fd = nqp_open("/0/5/9/hello.txt");

    printf("fd = %d\n", fd);

    // nqp_read(fd, &byte, 1);
    // printf("%c\n", byte);
    // nqp_read(fd, &byte, 1);
    // printf("%c\n", byte);
    // nqp_read(fd, &byte, 1);
    // printf("%c\n", byte);
    // nqp_read(fd, &byte, 1);
    // printf("%c\n", byte);
    size_t offset = 0;
    ssize_t bytes_read = 0;
    while ((bytes_read = nqp_read(fd, &buffer, read_bytes)) > 0) {
        // printf("%08zx: ", offset);

        // for (ssize_t i = 0; i < 16; i++) {
        //     printf("%02x", buffer[i]);
        //     if (i % 2 == 1) {
        //         printf(" ");
        //     }
        // }
        // printf("\n");
        offset += bytes_read;
        // for (ssize_t i = 0; i < bytes_read; i += 2) {
        //     if (i + 1 < 16) {
        //         // Print in little endian: second byte first, then first byte.
        //         printf("%02x%02x ", (unsigned char)buffer[i + 1],
        //                (unsigned char)buffer[i]);
        //     } else {
        //         // If the number of bytes is odd, just print the last byte.
        //         printf("%02x ", (unsigned char)buffer[i]);
        //     }
        // }
        // printf("\n");
        printf("%s", buffer);
    }
    printf("Num of bytes read: %d\n", (int)offset);
    // assert(err == NQP_OK);
    // err = nqp_unmount();
    // assert(err == NQP_OK);
    // err = nqp_mount(argv[2], NQP_FS_EXFAT);
    // assert(err == NQP_OK);
    // err = nqp_unmount();
    // assert(err == NQP_OK);
    return EXIT_SUCCESS;
}
