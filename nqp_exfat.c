#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
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
        ascii_string = malloc((sizeof(char) * length) + 1);

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

// Structure to represent an entry in the Open File Table.
typedef struct OPEN_FILE_TABLE_ENTRY {
    uint32_t file_fd;
    entry_set file_entry_set;
    uint32_t file_offset;
    uint32_t dirent_index;
} oft_e;

// Structure to represent the Open File Table.
typedef struct OPEN_FILE_TABLE {
    oft_e *entries;
    uint32_t add_index;
} oft;

// Global variables related to the mounted file system.
static char *mounted_fs = NULL;
static main_boot_record *mbr = NULL;
static uint32_t bytes_per_sector = 0;
static uint32_t sectors_per_clustor = 0;
static uint32_t fat_offset_bytes = 0;
static uint32_t cluster_heap_offset_bytes = 0;
static uint32_t size_of_cluster = 0;
static uint32_t directory_entry_per_cluster = 0;
static uint32_t nqp_fd = 2;
static oft *table = NULL;

// Structure to represent a node in a cluster chain.
struct CLUSTER_CHAIN_NODE {
    int cluster;
    struct CLUSTER_CHAIN_NODE *next;
};

// Structure to represent a list of entry sets.
typedef struct ENTRY_SET_LIST {
    entry_set *data;
    uint32_t add_index;
    uint32_t capacity;
} entry_set_list;

// Structure to represent a cluster chain.
struct CLUSTER_CHAIN {
    struct CLUSTER_CHAIN_NODE *head;
    struct CLUSTER_CHAIN_NODE *last;
    uint32_t size;
};

// Type definitions for cluster chain and its node.
typedef struct CLUSTER_CHAIN cluster_chain;
typedef struct CLUSTER_CHAIN_NODE cluster_chain_node;

/**
 * Initializes the Open File Table.
 * @return: A pointer to the initialized Open File Table.
 */
oft *init_open_file_table(void) {
    oft *table = malloc(sizeof(oft));
    table->add_index = 0;
    table->entries = malloc(sizeof(oft_e) * MAX_OPEN_FILES);
    return table;
}

/**
 * Adds an entry to the Open File Table.
 * @param table: Pointer to the Open File Table.
 * @param entry: The entry to add.
 */
void add_to_open_file_table(oft *table, oft_e entry) {
    table->entries[table->add_index] = entry;
    table->add_index++;
}

/**
 * Finds an entry in the Open File Table by file descriptor.
 * @param table: Pointer to the Open File Table.
 * @param fd: The file descriptor to search for.
 * @return: A pointer to the Open File Table entry, or NULL if not found.
 */
oft_e *find_oft_e(oft *table, uint32_t fd) {
    for (uint32_t i = 0; i < table->add_index; i++) {
        if (table->entries[i].file_fd == fd) {
            return &table->entries[i];
        }
    }

    return NULL;
}

/**
 * Removes an entry from the Open File Table.
 * @param table: Pointer to the Open File Table.
 * @param fd: The file descriptor of the entry to remove.
 * @return: 0 on success, -1 on failure.
 */
int remove_from_open_file_table(oft *table, uint32_t fd) {
    for (uint32_t i = 0; i < table->add_index; i++) {
        if (table->entries[i].file_fd == fd) {
            // Shift all elements to the left to fill the removed entry's space
            for (uint32_t j = i; j < table->add_index - 1; j++) {
                table->entries[j] = table->entries[j + 1];
            }

            // Decrement index
            table->add_index--;
            return 0;
        }
    }

    return -1;
}

/**
 * Resizes the entry set list to double its capacity.
 * @param list: Pointer to the entry set list.
 */
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

/**
 * Adds an entry set to the entry set list.
 * @param list: Pointer to the entry set list.
 * @param new_set: The entry set to add.
 */
void add_entry_set(entry_set_list *list, entry_set new_set) {
    if (list->add_index >= list->capacity) {
        resize_entry_set_list(list);
    }

    list->data[list->add_index++] = new_set;
}

/**
 * Initializes an entry set list.
 * @param init_size: The initial capacity of the list.
 * @return: A pointer to the initialized entry set list.
 */
entry_set_list *init_entry_set_list(int init_size) {
    entry_set_list *return_list = malloc(sizeof(*return_list));

    return_list->add_index = 0;
    return_list->capacity = init_size > 0 ? init_size : 4;
    return_list->data = malloc(sizeof(entry_set) * return_list->capacity);

    return return_list;
}

/**
 * Retrieves an entry set from an entry set list by index.
 * 
 * @param list Pointer to the entry set list.
 * @param index Index of the desired entry set.
 * @return Pointer to the entry set.
 */
entry_set *get_entry_set(entry_set_list *list, int index) {
    return &list->data[index];
}

/**
 * Creates and initializes a new cluster chain.
 * 
 * @return Pointer to the allocated cluster chain.
 */
cluster_chain *get_cluster_chain(void) {
    cluster_chain *return_chain = malloc(sizeof(*return_chain));
    return_chain->head = NULL;
    return_chain->last = NULL;
    return_chain->size = 0;
    return return_chain;
}

/**
 * Splits a string into substrings based on a given delimiter.
 * 
 * @param string The input string.
 * @param split_char The delimiter character.
 * @return Array of strings, NULL-terminated.
 */
char **split(const char *string, const char split_char) {
    int length = strlen(string);

    int num_words = 0;

    // Count occurrences of split_char to determine the number of words
    for (int i = 0; i < length; i++) {
        if (string[i] == split_char) {
            num_words++;
        }
    }

    num_words++; // Account for the last word

    // Allocate space for array of words (+1 for NULL termination)
    char **split_ary = (char **)malloc((num_words + 1) * sizeof(char *));

    char *copy = strdup(string);

    char *word = strtok(copy, (char[]){split_char, '\0'});

    for (int i = 0; i < num_words; i++) {
        if (word == NULL) {
            split_ary[i] = NULL; // Avoid accessing NULL
            break;
        }

        split_ary[i] = (char *)malloc(strlen(word) + 1);

        strcpy(split_ary[i], word);
        word = strtok(NULL, (char[]){split_char, '\0'}); // Get next token
    }

    split_ary[num_words] = NULL; // Null-terminate the array
    free(copy);                  // Free the duplicated string

    return split_ary;
}

/**
 * Retrieves the filename from an entry set.
 * 
 * @param es The entry set containing the filename.
 * @return Heap-allocated filename string.
 */
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

/**
 * Adds a cluster to a cluster chain.
 * 
 * @param chain Pointer to the cluster chain.
 * @param cluster Cluster ID to add.
 */
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

/**
 * Frees memory allocated for a cluster chain.
 * 
 * @param chain Pointer to the cluster chain.
 */
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

/**
 * Pre-condition checks for mounting a file system.
 * 
 * @param source The file system source.
 * @param fs_type The type of file system.
 */
void nqp_mount_pre(const char *source, nqp_fs_type fs_type) {
    assert(source != NULL);

    assert(fs_type == NQP_FS_TYPES || fs_type == NQP_FS_EXFAT);

    assert(mounted_fs == NULL);
}

/**
 * Validates the Main Boot Record of the file system.
 * 
 * @param mbr The main boot record structure.
 * @return Error code indicating success or failure.
 */
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
        size_of_cluster = bytes_per_sector * sectors_per_clustor;
        directory_entry_per_cluster = size_of_cluster / 32;
        nqp_fd = 2;
        table = init_open_file_table();
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
        if (table != NULL) {
            free(table);
            table = NULL;
        }
        nqp_fd = 2;
        return err;
    }
}

nqp_error nqp_unmount(void) {
    if (mounted_fs == NULL || mbr == NULL || table == NULL) {
        return NQP_INVAL;
    }

    free(mounted_fs);
    mounted_fs = NULL;
    free(mbr);
    mbr = NULL;
    free(table);
    table = NULL;
    nqp_fd = 2;

    return NQP_OK;
}

/**
 * Builds a cluster chain starting from the given cluster.
 * 
 * @param chain Pointer to the cluster chain.
 * @param first_cluster First cluster in the chain.
 */
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

/**
 * Fills an entry set list with directory entries when no FAT chain is used.
 * 
 * @param cluster The starting cluster of the directory.
 * @param list Pointer to the entry set list to populate.
 */
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

    uint8_t filenames_index = 0;
    read(fd, &read_de, 32);
    while (read_de.entry_type != 0x00) {
        // printf("entry_type = 0x%02X\n", read_de.entry_type);

        if (read_de.entry_type == FILE_DIRECTORY_ENTRY) {
            if (es.num_filenames > 0) {
                add_entry_set(list, es);
            }
            memset(&es, 0, sizeof(entry_set));
            es.file = read_de.file;
            es.num_filenames = 0;

        } else if (read_de.entry_type == STREAM_DIRECTORY_ENTRY) {
            es.stream_extension = read_de.stream_extension;
            es.filename =
                calloc(es.stream_extension.name_length + 1, sizeof(char));
            filenames_index = 0;
        } else if (read_de.entry_type == FILE_NAME_DIRECTORY_ENTRY) {
            if (es.num_filenames == 0) {
                es.filenames = malloc(sizeof(file_name) *
                                      17); // Allocate memory for filename parts
            }

            es.filenames[filenames_index] = read_de.file_name;
            es.num_filenames++;

            unicode2ascii_str = unicode2ascii(read_de.file_name.file_name, 15);
            strncat(es.filename, unicode2ascii_str, strlen(unicode2ascii_str));
            free(unicode2ascii_str);

            filenames_index++;
        }
        read(fd, &read_de, 32);
    }
    if (es.num_filenames > 0) {
        add_entry_set(list, es);
    }
    // printf("index = %d\n", index);
    close(fd);
}

/**
 * Fills an entry set list by traversing a cluster chain.
 * 
 * @param chain Pointer to the cluster chain.
 * @param list Pointer to the entry set list to populate.
 */
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
    uint8_t filenames_index = 0;
    read(fd, &read_de, 32);
    while (current != NULL && read_de.entry_type != 0x00) {
        if (read_de.entry_type == FILE_DIRECTORY_ENTRY) {
            if (es.num_filenames > 0) {
                add_entry_set(list, es);
            }
            memset(&es, 0, sizeof(entry_set));
            es.file = read_de.file;
            es.num_filenames = 0;

        } else if (read_de.entry_type == STREAM_DIRECTORY_ENTRY) {
            es.stream_extension = read_de.stream_extension;
            es.filename =
                calloc(es.stream_extension.name_length + 1, sizeof(char));
            filenames_index = 0;
        } else if (read_de.entry_type == FILE_NAME_DIRECTORY_ENTRY) {
            if (es.num_filenames == 0) {
                es.filenames = malloc(sizeof(file_name) *
                                      17); // Allocate memory for filename parts
            }

            es.filenames[filenames_index] = read_de.file_name;
            es.num_filenames++;

            unicode2ascii_str = unicode2ascii(read_de.file_name.file_name, 15);
            strncat(es.filename, unicode2ascii_str, strlen(unicode2ascii_str));
            free(unicode2ascii_str);

            filenames_index++;
        }

        if (index % directory_entry_per_cluster == 0) {
            current = current->next;
            // TODO: lseek
            lseek_offset = cluster_heap_offset_bytes +
                           ((current->cluster - 2) * bytes_per_sector *
                            sectors_per_clustor);
            lseek(fd, lseek_offset, SEEK_SET);
        }
        read(fd, &read_de, 32);
        index++;
    }
    if (es.num_filenames > 0) {
        add_entry_set(list, es);
    }

    // printf("index = %d\n", index);
    close(fd);
}

/**
 * Retrieves the entry set list for a given directory entry.
 * 
 * @param es The entry set representing the directory.
 * @return Pointer to an allocated entry set list.
 */
entry_set_list *get_dir_entry_set_list(entry_set es) {

    entry_set_list *list = init_entry_set_list(4);

    if (es.stream_extension.flags.no_fat_chain) {
        fill_entry_set_list_no_fat_chain(es.stream_extension.first_cluster,
                                         list);
    } else {
        cluster_chain *chain = get_cluster_chain();
        build_cluster_chain(chain, es.stream_extension.first_cluster);
        fill_entry_set_list(chain, list);
    }

    return list;
}

/**
 * Searches for a file within an entry set list by pathname.
 * 
 * @param list Pointer to the entry set list.
 * @param pathname The filename to search for.
 * @return Index of the file in the list, or -1 if not found.
 */
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

/**
 * Retrieves the root directory entry set list.
 * 
 * @param cluster The starting cluster of the root directory.
 * @return Pointer to an allocated entry set list.
 */
entry_set_list *get_root_dir_entry_set_list(int cluster) {
    entry_set_list *list = init_entry_set_list(4);
    cluster_chain *chain = get_cluster_chain();
    build_cluster_chain(chain, cluster);
    fill_entry_set_list(chain, list);

    return list;
}

/**
 * Retrieves the root entry set representing the root directory.
 * 
 * @return Pointer to the allocated root entry set.
 */
entry_set *get_root_entry_set(void) {
    entry_set *root_set = malloc(sizeof(*root_set));
    entry_set empty_set = {0};
    memcpy(root_set, &empty_set, sizeof(entry_set));

    root_set->filename = malloc(sizeof(char) * 2);
    root_set->filename[0] = '/';
    root_set->filename[1] = '\0';

    root_set->stream_extension.name_length = 1;
    root_set->stream_extension.first_cluster =
        mbr->first_cluster_of_root_directory;
    root_set->stream_extension.flags.no_fat_chain = 1;
    root_set->file.file_attributes = 16;

    return root_set;
}

/**
 * Finds a file in the file system given its pathname.
 * 
 * @param pathname The absolute path to the file.
 * @param fd Pointer to the file descriptor to store the result.
 * @return Pointer to the file's entry set, or NULL if not found.
 */
entry_set *find_file_in_system(const char *pathname, int *fd) {
    // printf("find_file_in_system called\n");
    if (strcmp(pathname, "/") == 0) {
        *fd = ++nqp_fd;
        return get_root_entry_set();
    }
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
            // printf("file_atte = %u\n", file_entry_set->file.file_attributes);
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
    if (pathname == NULL) {
        return NQP_INVAL;
    }

    if (mounted_fs == NULL) {
        return -1;
    }

    if (table->add_index >= MAX_OPEN_FILES) {
        return -3;
    }

    int fd = 0;
    entry_set *file_entry_set = NULL;
    file_entry_set = find_file_in_system(pathname, &fd);

    if (fd < 0) {
        return fd;
    }

    oft_e oft_entry = {0};
    oft_entry.file_fd = fd;
    oft_entry.file_entry_set = *file_entry_set;
    oft_entry.file_offset = 0;

    add_to_open_file_table(table, oft_entry);

    return fd;
}

int nqp_close(int fd) {

    if (fd < 0) {
        return NQP_INVAL;
    }

    int err = remove_from_open_file_table(table, fd);

    return err;
}

ssize_t normal_read(oft_e *fd_entry, void *buffer, size_t count) {
    ssize_t bytes_read = 0;
    uint32_t fd_cluster =
        fd_entry->file_entry_set.stream_extension.first_cluster;

    uint32_t lseek_offset =
        cluster_heap_offset_bytes +
        ((fd_cluster - 2) * bytes_per_sector * sectors_per_clustor) +
        fd_entry->file_offset;

    int fs_fd = open(mounted_fs, O_RDONLY);
    lseek(fs_fd, lseek_offset, SEEK_SET);

    uint32_t file_size = fd_entry->file_entry_set.stream_extension.data_length;

    uint32_t bytes_to_read = count < (file_size - fd_entry->file_offset)
                                 ? count
                                 : (file_size - fd_entry->file_offset);

    bytes_read = read(fd_entry->file_fd, buffer, bytes_to_read);
    fd_entry->file_offset += bytes_read;

    close(fs_fd);

    return bytes_read;
}

ssize_t fat_chain_read(oft_e *fd_entry, void *buffer, size_t count) {
    uint32_t temp_buffer[bytes_per_sector * sectors_per_clustor];
    ssize_t actual_bytes_read = 0;
    ssize_t bytes_read_in_loop = -1;
    uint32_t fd_cluster =
        fd_entry->file_entry_set.stream_extension.first_cluster;

    uint32_t lseek_offset = 0;
    uint32_t offset_in_cluster =
        fd_entry->file_offset % (bytes_per_sector * sectors_per_clustor);

    uint32_t cluster_in_chain =
        fd_entry->file_offset / (bytes_per_sector * sectors_per_clustor);

    cluster_chain *chain = get_cluster_chain();
    build_cluster_chain(chain, fd_cluster);
    cluster_chain_node *current = chain->head;
    for (uint32_t i = 0; i < cluster_in_chain; i++) {
        current = current->next;
    }
    uint32_t current_cluster_index = current->cluster - 2;
    uint32_t bytes_to_read = 0;
    uint32_t file_size = fd_entry->file_entry_set.stream_extension.data_length;

    lseek_offset =
        cluster_heap_offset_bytes +
        (current_cluster_index * bytes_per_sector * sectors_per_clustor) +
        offset_in_cluster;

    int fs_fd = open(mounted_fs, O_RDONLY);
    lseek(fs_fd, lseek_offset, SEEK_SET);

    while ((size_t)actual_bytes_read < count) {
        if (bytes_read_in_loop == 0) {
            if (actual_bytes_read != 0) {
                temp_buffer[0] = '\0';
                memcpy((char *)buffer + actual_bytes_read, &temp_buffer, 1);
                close(fs_fd);
                return actual_bytes_read;
            } else {
                ((char *)buffer)[0] = '\0';
                close(fs_fd);
                return 0;
            }
        }

        bytes_read_in_loop = 0;

        bytes_to_read =
            ((sectors_per_clustor * bytes_per_sector) - offset_in_cluster);
        bytes_to_read = bytes_to_read < (count - actual_bytes_read)
                            ? bytes_to_read
                            : (count - actual_bytes_read);

        // printf("Bytes 2 read(1): %d\n", bytes_to_read);
        bytes_to_read = bytes_to_read < (file_size - fd_entry->file_offset)
                            ? bytes_to_read
                            : (file_size - fd_entry->file_offset);
        // printf("Bytes 2 read(2): %d\n", bytes_to_read);

        bytes_read_in_loop += read(fs_fd, &temp_buffer, bytes_to_read);
        // printf("bytes_read_in_loop = %d\n", (int)bytes_read_in_loop);
        // if (bytes_read_in_loop == 0) {
        // }

        memcpy((char *)buffer + actual_bytes_read, (&temp_buffer),
               bytes_read_in_loop);
        actual_bytes_read += bytes_read_in_loop;
        // printf("actual bytes read (in loop): %d\n", (int)actual_bytes_read);

        fd_entry->file_offset += bytes_read_in_loop;
        if (current->next != NULL) {
            current = current->next;
            lseek_offset = (current->cluster - 2 - current_cluster_index - 1) *
                               (bytes_per_sector * sectors_per_clustor) +
                           1;
            current_cluster_index = current->cluster - 2;
            lseek(fs_fd, lseek_offset, SEEK_CUR);
        }
    }

    close(fs_fd);
    // printf("actual_bytes_read (before return): %d\n\n", (int)actual_bytes_read);
    return actual_bytes_read;
}

ssize_t nqp_read(int fd, void *buffer, size_t count) {
    // printf("Call to nqp_read\n");
    (void)fd;
    (void)buffer;
    (void)count;

    if (mounted_fs == NULL) {
        return NQP_INVAL;
    }

    if (fd < 0) {
        return NQP_INVAL;
    }

    oft_e *fd_entry = find_oft_e(table, fd);

    if (fd_entry == NULL) {
        return -1;
    }

    if (fd_entry->file_entry_set.file.file_attributes & 0x10) {
        return -2; // cannot read directories
    }

    // now we are at the start of the first cluster
    // if their is not fatchain than just add the
    // fd_offset from the fd_entry.
    // It there is cluster chain then build the cluster chain first,
    // and then based on the cluster chain go to correct offset to
    // read the data.
    ssize_t bytes_read = 0;
    if (fd_entry->file_offset >=
        fd_entry->file_entry_set.stream_extension.data_length) {
        ((char *)buffer)[0] = '\0';
        return 0;
    }
    if (fd_entry->file_entry_set.stream_extension.flags.no_fat_chain) {
        bytes_read = normal_read(fd_entry, buffer, count);
    } else {
        bytes_read = fat_chain_read(fd_entry, buffer, count);
    }

    return bytes_read;
}

ssize_t nqp_getdents(int fd, void *dirp, size_t count) {
    if (mounted_fs == NULL) {
        return NQP_INVAL;
    }

    if (dirp == NULL || fd < 0 || count < 1) {
        return NQP_INVAL;
    }

    oft_e *fd_entry = find_oft_e(table, fd);
    entry_set_list *list = init_entry_set_list(4);
    entry_set *fd_entry_set = NULL;
    nqp_dirent *new_entry = NULL;
    char *name = NULL;
    static uint64_t inode_no = 1;
    ssize_t return_count = 0;

    if (fd_entry == NULL) {
        return -1;
    }

    if (fd_entry->file_entry_set.file.file_attributes & 0x10) {
        list = get_dir_entry_set_list(fd_entry->file_entry_set);
        if (list == NULL) {
            return_count = -1;
        } else {
            for (size_t i = fd_entry->dirent_index;
                 (size_t)return_count < count && i < list->add_index; i++) {
                new_entry = malloc(sizeof(*new_entry));
                fd_entry_set = get_entry_set(list, i);
                new_entry->inode_number = inode_no;
                inode_no++;
                name = malloc((sizeof(char) *
                               fd_entry_set->stream_extension.name_length) +
                              1);
                strcpy(name, fd_entry_set->filename);
                new_entry->name = name;
                new_entry->name_len =
                    fd_entry_set->stream_extension.name_length;
                if (fd_entry_set->file.file_attributes & 0x10) {
                    new_entry->type = DT_DIR;
                } else {
                    new_entry->type = DT_REG;
                }

                memcpy((char *)dirp + (return_count * sizeof(nqp_dirent)),
                       new_entry, sizeof(nqp_dirent));
                return_count++;
            }
            fd_entry->dirent_index += return_count;
        }
    } else {
        return_count = -1;
    }

    return return_count;
}
