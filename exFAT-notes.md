- FAT: File Allocation Table
- Uses **little endian** encoding
- Volume: The file system and its contents
- Sector: Smallest size of physical storage unit in hard disk. In other words, sector is logical unit of hard disk, **generally** 512 bytes in size
- Cluster: Cluster is a consecutive group of sectors to store the data. It can be made of 1 or more sectors. Cluster is the logical unit of file system.
- Each volume contains **4** regions
  1. Main Boot region (12 sectors in size)
  2. Backup boot region
  3. FAT region
  4. Data region


