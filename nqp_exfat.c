#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
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
static uint32_t size_of_cluster = 0;
static uint32_t directory_entry_per_cluster = 0;
static int fs_fd = -1;

struct CLUSTER_CHAIN_NODE {
    int cluster;
    struct CLUSTER_CHAIN_NODE *next;
};

typedef struct {
    entry_set *data;
    uint32_t add_index;
    uint32_t capacity;
} entry_set_list;

struct CLUSTER_CHAIN {
    struct CLUSTER_CHAIN_NODE *head;
    struct CLUSTER_CHAIN_NODE *last;
    uint32_t size;
};

typedef struct CLUSTER_CHAIN cluster_chain;
typedef struct CLUSTER_CHAIN_NODE cluster_chain_node;

void resize_entry_set_list(entry_set_list *list) {
    uint32_t new_capacity = list->capacity * 2;
    entry_set *new_data = realloc(list->data, sizeof(entry_set) * new_capacity);

    if (!new_data) {
        perror("Failed to resize entry_set_list");
        exit(EXIT_FAILURE);
    }

    list->data = new_data;
    list->capacity = new_capacity;
}

void add_entry_set(entry_set_list *list, entry_set new_set) {
    if (list->add_index >= list->capacity) {
        resize_entry_set_list(list);
    }

    list->data[list->add_index++] = new_set;
}

entry_set_list *init_entry_set_list(int init_size) {
    entry_set_list *return_list = malloc(sizeof(*return_list));
    if (!return_list) {
        perror("Failed to allocate memory for entry_set_list");
        exit(EXIT_FAILURE);
    }

    return_list->add_index = 0;
    return_list->capacity = init_size > 0 ? init_size : 4;
    return_list->data = malloc(sizeof(entry_set) * return_list->capacity);

    if (!return_list->data) {
        perror("Failed to allocate memory for entry_set_list data");
        free(return_list);
        exit(EXIT_FAILURE);
    }

    return return_list;
}
entry_set *get_entry_set(entry_set_list *list, int index) {
    return &list->data[index];
}

char **split(const char *string, const char split_char) {
    // printf("<SPLIT> str recv: %s\n", string);
    int length = strlen(string);

    int num_words = 0;

    for (int i = 0; i < length; i++) {
        if (string[i] == split_char) {
            num_words++;
        }
    }

    num_words++;

    // adding extra space to append the NULL at end
    char **split_ary = (char **)malloc((num_words + 1) * sizeof(char *));

    char *copy = strdup(string);
    char *word;

    word = strtok(copy, (char[]){split_char, '\0'});
    for (int i = 0; i < num_words; i++) {
        split_ary[i] = (char *)malloc(sizeof(char) * (strlen(word) + 1));
        // printf("Adding %s\n", word);
        strcpy(split_ary[i], word);
        word = strtok(NULL, (char[]){split_char, '\0'});
    }

    split_ary[num_words] = NULL;

    return split_ary;
}

char *get_filename(entry_set es) {
    char *filename =
        malloc((sizeof(char) * es.stream_extension.name_length) + 1);
    char *unicode2ascii_str = NULL;
    for (int i = 0; i < es.num_filenames; i++) {
        unicode2ascii_str = unicode2ascii(es.filenames[i].file_name, 15);
        strcat(filename, unicode2ascii_str);
        free(unicode2ascii_str);
    }

    return filename;
}

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
        chain->size = 1;
    } else {
        // Append to the end of the chain
        chain->last->next = new_node;
        chain->last = new_node;
        chain->size += 1;
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
    // printf("nqp_mount called\n");
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
    // printf("fd = %d\n", fd);

    // printf("error before fd check\n");
    if (fd == -1) {
        printf("Error opening %s\n", source);
        return NQP_FILE_NOT_FOUND;
    }
    // printf("after fd error check\n");

    mbr = malloc(sizeof(*mbr));

    read(fd, mbr, 512);
    nqp_error err = validate_main_boot_region(*mbr);
    close(fd);

    if (err == NQP_OK) {
        mounted_fs = malloc(sizeof(char) * strlen(source) + 1); // 1 for \0 char
        strcpy(mounted_fs, source);
        bytes_per_sector = 1 << mbr->bytes_per_sector_shift;
        sectors_per_clustor = 1 << mbr->sectors_per_cluster_shift;
        fat_offset_bytes = mbr->fat_offset * (bytes_per_sector);
        // printf("fat_offset_bytes = %d\n fat_offset = %d\n", fat_offset_bytes,
        // mbr->fat_offset);
        cluster_heap_offset_bytes = mbr->cluster_heap_offset * bytes_per_sector;
        fs_fd = fd;
        size_of_cluster = bytes_per_sector * sectors_per_clustor;
        directory_entry_per_cluster = size_of_cluster / 32;
        // printf("size of cluster = %d\n", size_of_cluster);
        // printf("active FAT = %o\n", mbr->fs_flags);
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
    // printf("build_cluster_chain called\n");
    add_cluster_to_chain(chain, first_cluster);

    uint32_t fat_value = 0;
    uint32_t lseek_offset = fat_offset_bytes + ((first_cluster) * 4);
    // printf("lseek_offset = %u\n", lseek_offset);

    // printf("mounted_fs = %s\n", mounted_fs);
    int fd = open(mounted_fs, O_RDONLY);
    lseek(fd, lseek_offset, SEEK_SET);

    // We are at the fat cluster first_cluster
    // Now we will read 4 bytes till 0xffffffff is not fount and build up the cluster chain
    // printf("fd_fd = %d\n", fs_fd);
    read(fd, &fat_value, 4);
    // printf("fat_value = %d\n", fat_value);

    while (fat_value != 0xFFFFFFFF) {
        // printf("fat_value = %d\n", fat_value);
        add_cluster_to_chain(chain, fat_value);
        // printf("fat_value = %d\n", fat_value);

        lseek_offset = fat_offset_bytes + ((fat_value) * 4);
        lseek(fd, lseek_offset, SEEK_SET);
        read(fd, &fat_value, 4);
    }
    close(fd);
}

void fill_entry_set_list_no_fat_chain(int cluster, entry_set_list *list) {
    int fd = open(mounted_fs, O_RDONLY);

    char *unicode2ascii_str = NULL;
    directory_entry read_de = {0};
    entry_set es = {0};
    es.num_filenames = -1;

    uint32_t lseek_offset =
        cluster_heap_offset_bytes +
        ((cluster - 2) * bytes_per_sector * sectors_per_clustor);
    // printf("lseek_offset = %d\n", lseek_offset);
    lseek(fd, lseek_offset, SEEK_SET);

    uint8_t prev_entry_type = 0;
    uint8_t filenames_index = 0;
    read(fd, &read_de, 32);
    prev_entry_type = read_de.entry_type;
    while (read_de.entry_type != 0x00) {
        // printf("entry_type = 0x%02X\n", read_de.entry_type);

        // if (read_de.entry_type == FILE_DIRECTORY_ENTRY) {
        if (es.num_filenames != -1) {
            add_entry_set(list, es);
        }
        es.file = read_de.file;
        /*} else */ if (read_de.entry_type == STREAM_DIRECTORY_ENTRY) {
            es.stream_extension = read_de.stream_extension;
            es.filename =
                malloc((sizeof(char) * es.stream_extension.name_length) + 1);
        } else if (read_de.entry_type == FILE_NAME_DIRECTORY_ENTRY) {
            if (prev_entry_type == FILE_NAME_DIRECTORY_ENTRY) {
                es.filenames[filenames_index] = read_de.file_name;
                es.num_filenames = es.num_filenames + 1;

                unicode2ascii_str =
                    unicode2ascii(es.filenames[filenames_index].file_name, 15);
                strcat(es.filename, unicode2ascii_str);
                free(unicode2ascii_str);

                filenames_index++;
            } else {
                es.filenames = malloc(sizeof(file_name) * 17);
                filenames_index = 0;
                es.filenames[filenames_index] = read_de.file_name;
                es.num_filenames = 1;

                unicode2ascii_str =
                    unicode2ascii(es.filenames[filenames_index].file_name, 15);
                strcat(es.filename, unicode2ascii_str);
                free(unicode2ascii_str);

                filenames_index++;
            }
        }
        prev_entry_type = read_de.entry_type;
        read(fd, &read_de, 32);
    }
    // printf("index = %d\n", index);
    close(fd);
}

void fill_entry_set_list(cluster_chain *chain, entry_set_list *list) {
    int fd = open(mounted_fs, O_RDONLY);
    cluster_chain_node *current = chain->head;
    current = chain->head;

    char *unicode2ascii_str = NULL;
    directory_entry read_de = {0};
    entry_set es = {0};
    es.num_filenames = -1;

    uint32_t lseek_offset =
        cluster_heap_offset_bytes +
        ((current->cluster - 2) * bytes_per_sector * sectors_per_clustor);
    // printf("lseek_offset = %d\n", lseek_offset);
    lseek(fd, lseek_offset, SEEK_SET);

    uint32_t index = 1;
    uint8_t prev_entry_type = 0;
    uint8_t filenames_index = 0;
    read(fd, &read_de, 32);
    prev_entry_type = read_de.entry_type;
    while (current != NULL && read_de.entry_type != 0x00) {
        // printf("entry_type = 0x%02X\n", read_de.entry_type);

        // if (read_de.entry_type == FILE_DIRECTORY_ENTRY) {
        if (es.num_filenames != -1) {
            add_entry_set(list, es);
        }
        es.file = read_de.file;
        /*} else */ if (read_de.entry_type == STREAM_DIRECTORY_ENTRY) {
            es.stream_extension = read_de.stream_extension;
            es.filename =
                malloc((sizeof(char) * es.stream_extension.name_length) + 1);
        } else if (read_de.entry_type == FILE_NAME_DIRECTORY_ENTRY) {
            if (prev_entry_type == FILE_NAME_DIRECTORY_ENTRY) {
                es.filenames[filenames_index] = read_de.file_name;
                es.num_filenames = es.num_filenames + 1;

                unicode2ascii_str =
                    unicode2ascii(es.filenames[filenames_index].file_name, 15);
                strcat(es.filename, unicode2ascii_str);
                free(unicode2ascii_str);

                filenames_index++;
            } else {
                es.filenames = malloc(sizeof(file_name) * 17);
                filenames_index = 0;
                es.filenames[filenames_index] = read_de.file_name;
                es.num_filenames = 1;

                unicode2ascii_str =
                    unicode2ascii(es.filenames[filenames_index].file_name, 15);
                strcat(es.filename, unicode2ascii_str);
                free(unicode2ascii_str);

                filenames_index++;
            }
        }

        if (index % directory_entry_per_cluster == 0) {
            current = current->next;
            // TODO: lseek
            lseek_offset = cluster_heap_offset_bytes +
                           ((current->cluster - 2) * bytes_per_sector *
                            sectors_per_clustor);
            lseek(fd, lseek_offset, SEEK_SET);
        }
        prev_entry_type = read_de.entry_type;
        read(fd, &read_de, 32);
        index++;
    }
    // printf("index = %d\n", index);
    close(fd);
}

entry_set_list *get_dir_entry_set_list(entry_set es) {

    entry_set_list *list = init_entry_set_list(4);

    if (es.stream_extension.flags.no_fat_chain) {
        fill_entry_set_list_no_fat_chain(es.stream_extension.first_cluster,
                                         list);
    } else {
        cluster_chain *chain = malloc(sizeof(*chain));
        build_cluster_chain(chain, es.stream_extension.first_cluster);
        fill_entry_set_list(chain, list);
    }

    return list;
}

int find_file_in_list(entry_set_list *list, char *pathname) {
    // printf("list->add_index = %d\n", list->add_index);
    for (uint32_t i = 0; i < list->add_index; i++) {
        // printf("%d\n", i);
        if (strcmp(pathname, list->data[i].filename) == 0) {
            return i;
        }
    }

    return -1;
}

entry_set_list *get_root_dir_entry_set_list(int cluster) {
    entry_set_list *list = init_entry_set_list(4);
    cluster_chain *chain = malloc(sizeof(*chain));
    build_cluster_chain(chain, cluster);
    fill_entry_set_list(chain, list);

    return list;
}

entry_set *find_file_in_system(const char *pathname, int *fd) {
    // printf("find_file_in_system called\n");
    static int nqp_fd = 2;
    char **pathname_split = split(pathname, '/');
    entry_set *file_entry_set = malloc(sizeof(*file_entry_set));

    entry_set_list *list =
        get_root_dir_entry_set_list(mbr->first_cluster_of_root_directory);
    int index = 0;
    int get_index = 0;
    while (pathname_split[index] != NULL) {
        // printf("path_split = %s\n", pathname_split[index]);
        get_index = find_file_in_list(list, pathname_split[index]);
        if (get_index == -1) {
            free(file_entry_set);
            *fd = -1;
            break;
        }
        file_entry_set = get_entry_set(list, get_index);

        // checking for directory or not
        if (file_entry_set->file.file_attributes & 0x10) {
            // printf("file_attributes = %d\n",
            // file_entry_set->file.file_attributes);
            list = get_dir_entry_set_list(*file_entry_set);
        }
        index++;
    }

    if (*fd != -1) {
        *fd = ++nqp_fd;
    }
    return file_entry_set;
}

int nqp_open(const char *pathname) {
    // printf("nqp_open called\n");
    if (pathname == NULL) {
        return NQP_INVAL;
    }

    if (mounted_fs == NULL) {
        return -1;
    }

    // for (uint32_t i = 0; i < list->add_index; i++) {
    //     printf("File Entry Type: 0x%x\n", list->data[i].file.file_attributes);
    //     printf("First Cluster: %d\n",
    //            list->data[i].stream_extension.first_cluster);
    //     printf("File Name: %s\n\n", list->data[i].filename);
    // }

    // printf("just before find_file_in_system\n");
    int fd = 0;
    entry_set *file_entry_set = find_file_in_system(pathname, &fd);
    // printf("nqp_open returned");
    // Checking if the filepath is directory then returining -2
    // printf("file_attributes = %d\n", file_entry_set->file.file_attributes);

    if (file_entry_set->file.file_attributes & 0x10) {
        return -2;
    }

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
