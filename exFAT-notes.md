- FAT: File Allocation Table
- Uses **little endian** encoding
- Volume: The file system and its contents
- Sector: Smallest size of physical storage unit in hard disk. In other words, sector is logical unit of hard disk, **generally** 512 bytes in size
- Cluster: Cluster is a consecutive group of sectors to store the data. It can be made of 1 or more sectors. Cluster is the logical unit of file system.
- Each volume contains **4** regions
  1. Main Boot region ( **1** sector in size )
  2. Backup boot region
  3. FAT region
  4. Data region

- FatOffset: positon in the volume from where the first FAT starts. The positon is given in sectors, so need to convert it to bytes to get the actual positon and use lseek.
- ClusterHeapOffset: Positon in the volume where the first data cluster is located. The OffSet is in terms of sector, so need to convert it to bytes to use lseek.
- Note: The ClusterHeapOffset refers to cluster\[2\].
- VolumeFalgs\[0\]: ActiveFalg, describes which FAT, either 1 or 2, is active.
    - 0: First FAT and First Allocation bitmap
    - 1: Second FAT and Second Allocation bitmap
- FirstClusterOfRootDirectory: Refers to the root of the directory tree.
- 
