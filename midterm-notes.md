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

# Chapter 40

- A file system at its very least, has **Data region**, **Inode structure**, and every thing is devided in blocks.
- **Inode Structure**: It is responsible store information related to files like, size, modified time, access rights and more. Basically metadata for files.
- **Data Region**: Region when the actual data is stored.
- In **exFAT** the Inode structure(File type of directory entry) which is inside the cluster heap (data region). The FAT is there to figure out, where are the empty clusters in cluster chain and provide some data related to where can I find the actual data of the file.
- **Bitmap**: A simple data-strucute, whether the corrosponding object is free(0) or in-use(1).
- **Superblock**: Contains metadata related to file system.
- **Opening a file**: Start from root inode and then build the path to the file, by reading the inode, data block of the directories in the way. Once the file is found, then the fd is added to the open file table.
- **Reading a file**: Read the inode of the file to get the data block pointer, read the content from the data block. Once done, update the read offset in file's inode struct (write).
- **Creating a file**: Read the inodes to make the path just like opeaning the file. Then read inode bitmap to get the empty inode and write the inode bitmap. Then read the new file's inode and write to add information of new created file.
- **Writing a file**: Read the file's inode, then data bitmap to figure out empty data block then write the data bitmap and block, then write the file inode.

# Chapter 04

- OS starts the process in the following way:
  - It first load the code, static data into the virtual address space for the process.
  - There are two ways to load code and static data:
    1. **Egarly**: All data at once, old approach
    2. **Lazy**: Load data as needed, new approach
  - It then initialize runtime stack and head. argc and argv are added in stack.
  - Then the **3** file descriptors, **stdin**, **stdout** and **stderr** are initialized.
  - After this, it jumps to `main()` and executes the program and then handles the control of the CPU to the program
- **Process States**:
  1. **Running**: When the process is running, code is getting executed.
  2. **Ready**: Ready for running but OS decided not to run at that moment.
  3. **Blocked**: Process has performed some kind of operations that makes it not ready to run untill some other event takes place. Eg, waiting for user input.
  4. **Initial**: When the process is created.
  5. **Final**: Process is finished but the clean-up is not complete.
- At any given point a process can be described by state. State of process contains address space, CPU registers (program counter, stack pointer), and information about I/O.
- **Process API**:
  1. Start a process
  2. End a process
  3. Wait for process (wait for a process to over)
  4. Get status of the process
  5. Other controls: eg stop process from running untill resumed.
- OS has to keep track of all of the process (running, blocked, ready), when an I/O event completes, which process will run next. This is called **process list**, an entry of process list is called **process control block (PCB)**
- 
