#include "nqp_io.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {

    // int fd = 0;
    // ssize_t bytes_read = 0;
    // char buffer[256] = {0};
    // int exit_code = EXIT_SUCCESS;
    nqp_error err = nqp_mount(argv[1], NQP_FS_EXFAT);
    (void)argc;
    (void)err;
    nqp_open("root");
    // assert(err == NQP_OK);
    // err = nqp_unmount();
    // assert(err == NQP_OK);
    // err = nqp_mount(argv[2], NQP_FS_EXFAT);
    // assert(err == NQP_OK);
    // err = nqp_unmount();
    // assert(err == NQP_OK);
    return EXIT_SUCCESS;
}
