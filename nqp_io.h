#pragma once

#include <stdint.h>
#include <sys/types.h>

#define MAX_OPEN_FILES 8

typedef enum NQP_FS_TYPE
{
    NQP_FS_EXFAT,

    // NQP_FS_TYPES should always be last
    NQP_FS_TYPES
} nqp_fs_type;

typedef enum NQP_DIRECTORY_ENTRY_TYPE
{
    DT_DIR,  // a directory
    DT_REG,  // a regular file
} nqp_dtype;

typedef struct NQP_DIRECTORY_ENTRY
{
    uint64_t  inode_number; // the unique identifier for this entry
    size_t    name_len;     // the number of characters in the name
    char*     name;         // the actual name
    nqp_dtype type;         // the type of file that this points at
} nqp_dirent;

typedef enum NQP_ERROR
{
    NQP_OK = 0,              // no error.

    NQP_UNSUPPORTED_FS = -1, // this file system is not supported by the
                             // implementation.

    NQP_FSCK_FAIL = -2,      // the file system's super block did not pass the
                             // basic file system check.

    NQP_INVAL = -3,          // an invalid argment was passed.

    NQP_FILE_NOT_FOUND = -4, // no file with the given name was found.

} nqp_error;

/**
 * "Mount" a file system.
 *
 * This function must be called before interacting with any other nqp_*
 * functions (they will all use the "mounted" file system).
 *
 * This function does a basic file system check on the super block of the file 
 * system being mounted.
 *
 * Parameters:
 *  * source: The file containing the file system to mount. Must not be NULL.
 *  * fs_type: The type of the file system. Must be a value from nqp_fs_type.
 * Return: NQP_UNSUPPORTED_FS if the current implementation does not support
 *         the file system specified, NQP_FSCK_FAIL if the super block does not
 *         pass the basic file system check, NQP_INVAL if an invalid argument
 *         has been passed (e.g., NULL),or NQP_OK on success.
 */
nqp_error nqp_mount( const char *source, nqp_fs_type fs_type );

/**
 * "Unmount" the mounted file system.
 *
 * This function should be called to flush any changes to the file system's 
 * volume (there shouldn't be! All operations are read only.)
 *
 * Return: NQP_INVAL on error (e.g., there is no fs currently mounted) or
 *         NQP_OK on success.
 */
nqp_error nqp_unmount( void );

/**
 * Open the file at pathname in the "mounted" file system.
 *
 * Parameters:
 *  * pathname: The path of the file or directory in the file system that
 *              should be opened.  Must not be NULL.
 * Return: -1 on error, or a nonnegative integer on success. The nonnegative
 *         integer is a file descriptor.
 */
int nqp_open( const char *pathname );

/**
 * Close the file referred to by the descriptor.
 *
 * Parameters:
 *  * fd: The file descriptor to close. Must be a nonnegative integer.
 * Return: -1 on error or 0 on success.
 */
int nqp_close( int fd );

/**
 * Read from a file desriptor.
 *
 * Parameters:
 *  * fd: The file descriptor to read from. Must be a nonnegative integer. The
 *        file descriptor should refer to a file, not a directory.
 *  * buffer: The buffer to read data into. Must not be NULL.
 *  * count: The number of bytes to read into the buffer.
 * Return: The number of bytes read, 0 at the end of the file, or -1 on error.
 */
ssize_t nqp_read( int fd, void *buffer, size_t count );

/**
 * Get the directory entries for a directory. Similar to read()ing a file, you
 * may need to call this function repeatedly to get all directory entries.
 *
 * Parameters:
 *  * fd: The file descriptor to read from. Must be a nonnegative integer. The
 *        file descriptor should refer to a directory, not a file.
 *  * dirp: the buffer into which the directory entries will be written. The
 *          buffer must not be NULL.
 *  * count: the size of the buffer. Must be at least sizeof(nqp_dirent).
 * Return: The total number of bytes read into the buffer, 0 at the end of the
 * directory, or -1 on error.
 */
ssize_t nqp_getdents( int fd, void *dirp, size_t count );

#ifdef USE_LIBC_INSTEAD

#include <fcntl.h>
#include <unistd.h>

// these replace our implementation with the standard libc implementations of
// open, read, and close, so that we can get a sense of how the tests are 
// supposed to work.
#define nqp_read( fd, buffer, size ) read( fd, buffer, size )
#define nqp_open( name ) open( name, O_RDONLY )
#define nqp_close( fd ) close( fd )

// mount and unmount are not functions we would be able to call, so straight
// up replace these with NQP_OK, code expecting NQP_OK will just pass through.
#define nqp_mount(name, type) NQP_OK
#define nqp_unmount() NQP_OK

#endif
