# Chapter 39

- unlink() is used to remove files
- **Creating a File**: Create with open system call, once file is created it is added to the open file table
- **Reading and Writing File**: use read and write ssystem call. Use lseek to jump to a certain part of the file to read/write **not** sequencially.
- **Write Immediately**: To do it use fsync() to do it. For performance reason, OS buffer writes and then perform all at once.
- **Rename a File**: Use rename() system call for it. It is **atomic** system call, meaning it is gauranted that the file will have either old name or the new name, there is not in between. Atomic operation means that its either executed completly or it is not executed at all.
- **Info realted to File**: Use stat call to do it. stat is a command not a system call. In this section we got to know that os stores a bunch of information like last modified, creator id and more related to files. Somewhat similar information are found in **File Dentry** in exFAT.
- **Making directories**: You can make dir by mkdir call. You can directly never write to directory because it is a special type of file and contains information in a specific format. The file struct have permission in it. Where as dirent does not have that.
- **Deleting a dir**: rmdir to delete. Dir should be empty else rmdir will fail
- **Hard Links**: When you link a file with another file, both of the file point to same inode structure. This link of same inode to the different human readeable is stored in ref field in inode struct. When unlink is called it the ref is decreased by 1 and it removes link from the inode struct to the human readeable name provided. It is only when the ref is 0 file is deleted from the system.
- **Symbolic links**: Also called as soft link. Works same as hard link but when the original file is deleted then the files with soft links are also deleted.
- 
- 
