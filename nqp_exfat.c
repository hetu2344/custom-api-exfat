#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "nqp_exfat_types.h"
#include "nqp_io.h"

/**
 * Convert a Unicode-formatted string containing only ASCII characters
 * into a regular ASCII-formatted string (16 bit chars to 8 bit 
 * chars).
 *
 * NOTE: this function does a heap allocation for the string it 
 *       returns (like strdup), caller is responsible for `free`-ing the
 *       allocation when necessary.
 *
 * uint16_t *unicode_string: the Unicode-formatted string to be 
 *                           converted.
 * uint8_t   length: the length of the Unicode-formatted string (in
 *                   characters).
 *
 * returns: a heap allocated ASCII-formatted string.
 */
char *unicode2ascii(uint16_t *unicode_string, uint8_t length) {
    assert(unicode_string != NULL);
    assert(length > 0);

    char *ascii_string = NULL;

    if (unicode_string != NULL && length > 0) {
        // +1 for a NULL terminator
        ascii_string = calloc(sizeof(char), length + 1);

        if (ascii_string) {
            // strip the top 8 bits from every character in the
            // unicode string
            for (uint8_t i = 0; i < length; i++) {
                ascii_string[i] = (char)unicode_string[i];
            }
            // stick a null terminator at the end of the string.
            ascii_string[length] = '\0';
        }
    }

    return ascii_string;
}

static char *mounted_fs = NULL;
static main_boot_record *mbr = NULL;
static uint32_t bytes_per_sector = 0;
static uint32_t sectors_per_clustor = 0;
static uint32_t fat_offset_bytes = 0;
static uint32_t cluster_heap_offset_bytes = 0;
static int fs_fd = -1;

struct CLUSTER_CHAIN_NODE {
    int cluster;
    struct CLUSTER_CHAIN_NODE *next;
};

struct CLUSTER_CHAIN {
    struct CLUSTER_CHAIN_NODE *head;
    struct CLUSTER_CHAIN_NODE *last;
};

typedef struct CLUSTER_CHAIN cluster_chain;
typedef struct CLUSTER_CHAIN_NODE cluster_chain_node;

void add_cluster_to_chain(cluster_chain *chain, int cluster) {

    cluster_chain_node *new_node = malloc(sizeof(cluster_chain_node));
    if (new_node == NULL) {
        // Handle memory allocation failure
        return;
    }

    new_node->cluster = cluster;
    new_node->next = NULL;

    if (chain->head == NULL) {
        // First node in the chain
        chain->head = new_node;
        chain->last = new_node;
    } else {
        // Append to the end of the chain
        chain->last->next = new_node;
        chain->last = new_node;
    }
}

void free_cluster_chain(cluster_chain *chain) {
    cluster_chain_node *current = chain->head;
    cluster_chain_node *temp = NULL;
    while (current != NULL) {
        temp = current;
        current = current->next;
        free(temp);
    }
    free(chain);
}

// preconditions for the mount function
void nqp_mount_pre(const char *source, nqp_fs_type fs_type) {
    assert(source != NULL);

    assert(fs_type == NQP_FS_TYPES || fs_type == NQP_FS_EXFAT);

    assert(mounted_fs == NULL);
}

// function to validate the contents of Main Boot Region
nqp_error validate_main_boot_region(main_boot_record mbr) {
    // checking the boot signature is 0xAA55 or not
    if (mbr.boot_signature != BOOT_SIGNATURE) {
        return NQP_FSCK_FAIL;
    }

    if (strcmp(mbr.fs_name, "EXFAT   ") != 0) {
        return NQP_FSCK_FAIL;
    }

    // Checking for 53 must be zero bits
    for (uint8_t i = 0; i < 53; i++) {
        // printf("must_be_zero[%d] = %u\n", i, mbr.must_be_zero[i]);
        if (mbr.must_be_zero[i] != 0) {
            return NQP_FSCK_FAIL;
        }
    }

    // Checking for the reange of first cluster of the root directory
    if (mbr.first_cluster_of_root_directory < 2 ||
        mbr.first_cluster_of_root_directory > mbr.cluster_count + 1) {
        return NQP_FSCK_FAIL;
    }
    // printf("First cluster of root directory: %u\n",
    // mbr.first_cluster_of_root_directory);

    return NQP_OK;
}

nqp_error nqp_mount(const char *source, nqp_fs_type fs_type) {
    (void)source;
    (void)fs_type;
    printf("nqp_mount called\n");
    // pre-conditions
    nqp_mount_pre(source, fs_type);

    // open the file system
    if (source == NULL) {
        return NQP_INVAL;
    }

    if (fs_type != NQP_FS_TYPES && fs_type != NQP_FS_EXFAT) {
        return NQP_UNSUPPORTED_FS;
    }

    int fd = open(source, O_RDONLY);
    printf("fd = %d\n", fd);

    printf("error before fd check\n");
    if (fd == -1) {
        printf("Error opening %s\n", source);
        return NQP_FILE_NOT_FOUND;
    }
    printf("after fd error check\n");

    mbr = malloc(sizeof(*mbr));

    read(fd, mbr, 512);
    nqp_error err = validate_main_boot_region(*mbr);

    if (err == NQP_OK) {
        mounted_fs = malloc(sizeof(char) * strlen(source) + 1); // 1 for \0 char
        strcpy(mounted_fs, source);
        bytes_per_sector = 1 << mbr->bytes_per_sector_shift;
        sectors_per_clustor = 1 << mbr->sectors_per_cluster_shift;
        fat_offset_bytes = mbr->fat_offset * (bytes_per_sector);
        cluster_heap_offset_bytes = mbr->cluster_heap_offset * bytes_per_sector;
        fs_fd = fd;
        // printf("Current mounted file system is \"%s\"\n", mounted_fs);
        return NQP_OK;
    } else {
        if (mounted_fs != NULL) {
            free(mounted_fs);
            mounted_fs = NULL;
        }
        if (mbr != NULL) {
            free(mbr);
            mbr = NULL;
        }
        fs_fd = -1;
        return err;
    }
}

nqp_error nqp_unmount(void) {
    if (mounted_fs == NULL) {
        return NQP_INVAL;
    }

    if (mbr == NULL) {
        return NQP_INVAL;
    }
    // printf("File system unmounted\n");
    free(mounted_fs);
    mounted_fs = NULL;
    free(mbr);
    mbr = NULL;
    fs_fd = -1;
    return NQP_OK;
}

void build_cluster_chain(cluster_chain *chain, int first_cluster) {
    printf("build_cluster_chain called\n");
    add_cluster_to_chain(chain, first_cluster);

    uint32_t fat_value = 0;
    off_t lseek_offset = fat_offset_bytes * (first_cluster - 1) * 4;
    lseek(fs_fd, lseek_offset, SEEK_SET);

    // We are at the fat cluster first_cluster
    // Now we will read 4 bytes till 0xffffffff is not fount and build up the cluster chain
    read(fs_fd, &fat_value, 4);

    while (fat_value != 0xFFFFFFFF) {
        add_cluster_to_chain(chain, fat_value);
        read(fs_fd, &fat_value, 4);
    }
}

int nqp_open(const char *pathname) {
    printf("nqp_open called\n");
    if (pathname == NULL) {
        return NQP_INVAL;
    }

    if (mounted_fs == NULL) {
        return -1;
    }

    static int fd = 3;

    cluster_chain *chain = malloc(sizeof(cluster_chain));
    build_cluster_chain(chain, mbr->first_cluster_of_root_directory);
    cluster_chain_node *current = chain->head;
    while (current != NULL) {
        printf("%d --> ", current->cluster);
        current = current->next;
    }
    printf("NULL\n");

    printf("nqp_open returned");
    return fd;
}

int nqp_close(int fd) {
    (void)fd;

    return NQP_INVAL;
}

ssize_t nqp_read(int fd, void *buffer, size_t count) {
    (void)fd;
    (void)buffer;
    (void)count;

    return NQP_INVAL;
}
