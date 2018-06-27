#include "KernelVMFileSystem.h"
#include "errno.h"
#include "sys/types.h"
#include "sys/stat.h"

#define S_IFLNK 0x3000;

const uint64_t VMFS_EXTENT_BASE(15472640);
const uint64_t SECTER_SIZE(512);

#define LE_AND_NO_ALIGN 1

int vmfs_file_close(vmfs_file *f)
{
	if (f == NULL)
		return(-1);

	if (f->flags & VMFS_FILE_FLAG_FD)
		CloseHandle(f->fd);

	free(f);
	return(0);
}

static inline char *strndup(const char *s, size_t n) {
	char *result;
	n = strnlen(s, n);
	result = (char * )malloc(n + 1);
	if (!result)
		return NULL;
	memcpy(result, s, n);
	result[n] = 0;
	return result;
}

static inline uint16_t read_le16(const u_char *p,int offset)
{
#ifdef LE_AND_NO_ALIGN
	return(*((uint16_t *)&p[offset]));
#else
	return((uint16_t)p[offset] | ((uint16_t)p[offset+1] << 8));
#endif
}

/* Read a 32-bit word in little endian format */
static inline uint32_t read_le32(const u_char *p,int offset)
{
#ifdef LE_AND_NO_ALIGN
	return(*((uint32_t *)&p[offset]));
#else
	return((uint32_t)p[offset] |
		((uint32_t)p[offset+1] << 8) |
		((uint32_t)p[offset+2] << 16) |
		((uint32_t)p[offset+3] << 24));
#endif
}

/* Read a 64-bit word in little endian format */
static inline uint64_t read_le64(const u_char *p,int offset)
{
#ifdef LE_AND_NO_ALIGN
	return(*((uint64_t *)&p[offset]));
#else
	return((uint64_t)read_le32(p,offset) +
		((uint64_t)read_le32(p,offset+4) << 32));
#endif
}

/* Allocate a buffer with alignment compatible for direct I/O */
u_char *iobuffer_alloc(size_t len)
{
	size_t buf_len;
	void *buf;

	buf_len = ALIGN_NUM(len,M_DIO_BLK_SIZE);

	if (!(buf = _aligned_malloc(M_DIO_BLK_SIZE,buf_len))) return NULL;

	return (u_char * )buf;
}

ssize_t m_read(HANDLE hFile, byte * buffer, uint32_t size, uint64_t pos)
{
	OVERLAPPED oTmp = {0};
	pos += VMFS_EXTENT_BASE * SECTER_SIZE;
	oTmp.Offset = pos & 0xFFFFFFFF;
	oTmp.OffsetHigh = pos >> 32;

	DWORD lenRead;
	ReadFile(hFile, buffer, size, &lenRead, &oTmp);

	return (ssize_t)lenRead;
}

/* Read a raw block of data on logical volume */
ssize_t vmfs_vol_read(HANDLE hDevice,off_t pos,
							 u_char *buf,size_t len)
{
	pos += VMFS_VOLINFO_BASE + 0x1000000;

	return(m_read(hDevice, buf, len, pos));
}


KernelVMFileSystem::KernelVMFileSystem():device(NULL)
{
}

KernelVMFileSystem::KernelVMFileSystem(HANDLE hDisk):device(hDisk)
{
	inode_hash_buckets = VMFS_INODE_HASH_BUCKETS;
	inodes = (vmfs_inode **)calloc(inode_hash_buckets,sizeof(vmfs_inode *));

	if (vmfs_volinfo_read() == -1)
	{
		fprintf(stderr,"VMFS: Unable to read VOL information\n");
	}

	/* Read FS info */
	if (vmfs_fsinfo_read() == -1) {
		fprintf(stderr,"VMFS: Unable to read FS information\n");
	}

	/* Read FDC base information */
	if (vmfs_read_fdc_base() == -1) {
		fprintf(stderr,"VMFS: Unable to read FDC information\n");
	}

}

KernelVMFileSystem::~KernelVMFileSystem()
{
}

/* Read a block from the filesystem */
ssize_t KernelVMFileSystem::vmfs_fs_read(uint32_t blk,off_t offset,
					 u_char *buf,size_t len)
{
	off_t pos;

	pos  = (uint64_t)blk * fs_info.block_size;
	pos += offset;

	return(vmfs_vol_read(device, pos, buf, len));
}

/* Read volume information */
int KernelVMFileSystem::vmfs_volinfo_read()
{
   DECL_ALIGNED_BUFFER(buf,1024);

   if (m_read(device, buf, buf_len, VMFS_VOLINFO_BASE) != buf_len)
      return(-1);

   vol_info.magic = read_le32(buf,VMFS_VOLINFO_OFS_MAGIC);

   if (vol_info.magic != VMFS_VOLINFO_MAGIC) {
      fprintf(stderr,"VMFS VolInfo: invalid magic number 0x%8.8x\n",
              vol_info.magic);
      return(-1);
   }

   vol_info.version = read_le32(buf,VMFS_VOLINFO_OFS_VER);
   vol_info.size = read_le32(buf,VMFS_VOLINFO_OFS_SIZE);
   vol_info.lun = buf[VMFS_VOLINFO_OFS_LUN];

   vol_info.name = strndup((char *)buf+VMFS_VOLINFO_OFS_NAME,
                       VMFS_VOLINFO_OFS_NAME_SIZE);

   memcpy_s(&vol_info.uuid, sizeof(MyUUID), buf + VMFS_VOLINFO_OFS_UUID, sizeof(MyUUID));

   vol_info.lvm_size = read_le64(buf,VMFS_LVMINFO_OFS_SIZE);
   vol_info.blocks  = read_le64(buf,VMFS_LVMINFO_OFS_BLKS);
   vol_info.num_segments = read_le32(buf,VMFS_LVMINFO_OFS_NUM_SEGMENTS);
   vol_info.first_segment = read_le32(buf,VMFS_LVMINFO_OFS_FIRST_SEGMENT);
   vol_info.last_segment = read_le32(buf,VMFS_LVMINFO_OFS_LAST_SEGMENT);
   vol_info.num_extents = read_le32(buf,VMFS_LVMINFO_OFS_NUM_EXTENTS);
   memcpy_s(&vol_info.lvm_uuid, sizeof(MyUUID), buf + VMFS_LVMINFO_OFS_UUID, sizeof(MyUUID));

   return(0);
}

/* Read filesystem information */
int KernelVMFileSystem::vmfs_fsinfo_read()
{
	DECL_ALIGNED_BUFFER(buf,512);

	if (vmfs_vol_read(device, VMFS_FSINFO_BASE, buf, buf_len) != buf_len)
		return(-1);

	fs_info.magic = read_le32(buf, VMFS_FSINFO_OFS_MAGIC);

	if (fs_info.magic != VMFS_FSINFO_MAGIC) {
		fprintf(stderr,"VMFS FSInfo: invalid magic number 0x%8.8x\n",fs_info.magic);
		return(-1);
	}

	fs_info.vol_version      = read_le32(buf,VMFS_FSINFO_OFS_VOLVER);
	fs_info.version          = buf[VMFS_FSINFO_OFS_VER];
	fs_info.mode             = read_le32(buf,VMFS_FSINFO_OFS_MODE);
	fs_info.block_size       = read_le64(buf,VMFS_FSINFO_OFS_BLKSIZE);
	fs_info.subblock_size    = read_le32(buf,VMFS_FSINFO_OFS_SBSIZE);
	fs_info.fdc_header_size  = read_le32(buf,VMFS_FSINFO_OFS_FDC_HEADER_SIZE);
	fs_info.fdc_bitmap_count = read_le32(buf,VMFS_FSINFO_OFS_FDC_BITMAP_COUNT);
	fs_info.ctime            = (time_t)read_le32(buf,VMFS_FSINFO_OFS_CTIME);

	memcpy_s(&fs_info.uuid, sizeof(MyUUID), buf + VMFS_FSINFO_OFS_UUID, sizeof(MyUUID));
	fs_info.label = strndup((char *)buf+VMFS_FSINFO_OFS_LABEL,
		VMFS_FSINFO_OFS_LABEL_SIZE);
	memcpy_s(&fs_info.lvm_uuid, sizeof(MyUUID), buf + VMFS_FSINFO_OFS_LVM_UUID, sizeof(MyUUID));

	return(0);
}

/* Get number of items per area */
inline u_int
KernelVMFileSystem::vmfs_bitmap_get_items_per_area(const vmfs_bitmap_header *bmh)
{
	return(bmh->bmp_entries_per_area * bmh->items_per_bitmap_entry);
}

/* Get position of an item */
off_t KernelVMFileSystem::vmfs_bitmap_get_item_pos(vmfs_bitmap *b,uint32_t entry,uint32_t item)
{
	off_t pos;
	uint32_t addr;
	uint32_t items_per_area;
	u_int area;

	addr = (entry * b->bmh.items_per_bitmap_entry) + item;

	items_per_area = vmfs_bitmap_get_items_per_area(&b->bmh);
	area = addr / items_per_area;

	pos  = b->bmh.hdr_size + (area * b->bmh.area_size);
	pos += b->bmh.bmp_entries_per_area * VMFS_BITMAP_ENTRY_SIZE;
	pos += (addr % items_per_area) * b->bmh.data_size;

	return(pos);
}


/* Read a bitmap item from its entry and item numbers */
bool KernelVMFileSystem::vmfs_bitmap_get_item(vmfs_bitmap *b, uint32_t entry, uint32_t item,
						  u_char *buf)
{
	off_t pos = vmfs_bitmap_get_item_pos(b,entry,item);
	return(vmfs_file_pread(b->f,buf,b->bmh.data_size,pos) == b->bmh.data_size);
}

/* Read a piece of a file block */
ssize_t KernelVMFileSystem::vmfs_block_read_fb(uint32_t blk_id,off_t pos,
						   u_char *buf,size_t len)
{
	uint64_t offset,n_offset,blk_size;
	size_t clen,n_clen;
	uint32_t fb_item;
	u_char *tmpbuf;

	blk_size = fs_info.block_size;

	offset = pos % blk_size;
	clen   = m_min(blk_size - offset,len);

	/* Use "normalized" offset / length to access data (for direct I/O) */
	n_offset = offset & ~(M_DIO_BLK_SIZE - 1);
	n_clen   = ALIGN_NUM(clen + (offset - n_offset),M_DIO_BLK_SIZE);

	fb_item = VMFS_BLK_FB_ITEM(blk_id);

	/* If everything is aligned for direct I/O, store directly in user buffer */
	if ((n_offset == offset) && (n_clen == clen) &&
		ALIGN_CHECK((uintptr_t)buf,M_DIO_BLK_SIZE))
	{
		if (vmfs_fs_read(fb_item,n_offset,buf,n_clen) != n_clen)
			return(-EIO);

		return(n_clen);
	}

	/* Allocate a temporary buffer and copy result to user buffer */
	if (!(tmpbuf = new u_char[n_clen]))
		return(-1);

	if (vmfs_fs_read(fb_item,n_offset,tmpbuf,n_clen) != n_clen) {
		free(tmpbuf);
		return(-EIO);
	}

	memcpy(buf,tmpbuf+(offset-n_offset),clen);

	delete [] tmpbuf;
	return(clen);
}

/* Read a piece of a sub-block */
ssize_t KernelVMFileSystem::vmfs_block_read_sb(uint32_t blk_id,off_t pos,
						   u_char *buf,size_t len)
{
	u_char * tmpbuf(NULL);
	DECL_ALIGNED_BUFFER_WOL(tmpbuf,sbc->bmh.data_size);
	uint32_t offset,sbc_entry,sbc_item;
	size_t clen;

	offset = pos % sbc->bmh.data_size;
	clen   = m_min(sbc->bmh.data_size - offset,len);

	sbc_entry = VMFS_BLK_SB_ENTRY(blk_id);
	sbc_item  = VMFS_BLK_SB_ITEM(blk_id);

	if (!vmfs_bitmap_get_item(sbc,sbc_entry,sbc_item,tmpbuf))
		return(-EIO);

	memcpy(buf,tmpbuf+offset,clen);
	return(clen);
}


int KernelVMFileSystem::vmfs_inode_get_block(const vmfs_inode *inode,off_t pos,uint32_t *blk_id)
{
   u_int blk_index;
   uint32_t zla;
   int vmfs5_extension;

   *blk_id = 0;

   if (!inode->blk_size)
      return(-EIO);

   /* This doesn't make much sense but looks like how it's being coded. At
    * least, the result has some sense. */
   zla = inode->zla;
   if (zla >= VMFS5_ZLA_BASE) {
      vmfs5_extension = 1;
      zla -= VMFS5_ZLA_BASE;
   } else
      vmfs5_extension = 0;

   switch(zla) {
      case VMFS_BLK_TYPE_FB:
      case VMFS_BLK_TYPE_SB:
         blk_index = pos / inode->blk_size;
         
         if (blk_index >= VMFS_INODE_BLK_COUNT)
            return(-EINVAL);

         *blk_id = inode->blocks[blk_index];
         break;

      case VMFS_BLK_TYPE_PB:
      {
		 u_char * buf(NULL);
         DECL_ALIGNED_BUFFER_WOL(buf,pbc->bmh.data_size);
         uint32_t pb_blk_id;
         uint32_t blk_per_pb;
         u_int pb_index;
         u_int sub_index;

         blk_per_pb = pbc->bmh.data_size / sizeof(uint32_t);
         blk_index = pos / inode->blk_size;

         pb_index  = blk_index / blk_per_pb;
         sub_index = blk_index % blk_per_pb;

         if (pb_index >= VMFS_INODE_BLK_COUNT)
            return(-EINVAL);

         pb_blk_id = inode->blocks[pb_index];

         if (!pb_blk_id)
            break;

         if (!vmfs_bitmap_get_item(pbc,
                                   VMFS_BLK_PB_ENTRY(pb_blk_id),
                                   VMFS_BLK_PB_ITEM(pb_blk_id),
                                   buf))
            return(-EIO);

         memcpy_s(blk_id, sizeof(uint32_t),buf + sub_index*sizeof(uint32_t), sizeof(uint32_t));
		 delete buf;
		 buf = NULL;
         break;
      }

      case VMFS_BLK_TYPE_FD:
         if (vmfs5_extension) {
            *blk_id = inode->id;
            break;
         }
      default:
         /* Unexpected ZLA type */
         return(-EIO);
   }

   return(0);
}

/* Read data from a file at the specified position */
ssize_t KernelVMFileSystem::vmfs_file_pread(vmfs_file *f,u_char *buf,size_t len,off_t pos)
{
	uint32_t blk_id,blk_type;
	uint64_t blk_size,blk_len;
	uint64_t file_size,offset;
	ssize_t res = 0,rlen = 0;
	size_t exp_len;
	int err;

	if (f->flags & VMFS_FILE_FLAG_FD)
		return m_read(f->fd, buf, len, pos);

	/* We don't handle RDM files */
	if (f->inode->type == VMFS_FILE_TYPE_RDM)
		return(-EIO);

	blk_size = fs_info.block_size;
	file_size = f->GetFileSize();

	while(len > 0) {
		if (pos >= file_size)
			break;

		if ((err = vmfs_inode_get_block(f->inode,pos,&blk_id)) < 0)
			return(err);

		blk_type = VMFS_BLK_FB_TBZ(blk_id) ? VMFS_BLK_TYPE_NONE : VMFS_BLK_TYPE(blk_id);

		switch(blk_type) {
			/* Unallocated block */
		 case VMFS_BLK_TYPE_NONE:
			 offset = pos % blk_size;
			 blk_len = blk_size - offset;
			 exp_len = m_min(blk_len,len);
			 res = m_min(exp_len,file_size - pos);
			 memset(buf,0,res);
			 break;

			 /* File-Block */
		 case VMFS_BLK_TYPE_FB:
			 exp_len = m_min(len,file_size - pos);
			 res = vmfs_block_read_fb(blk_id,pos,buf,exp_len);
			 break;

			 /* Sub-Block */
		 case VMFS_BLK_TYPE_SB: {
			 exp_len = m_min(len,file_size - pos);
			 res = vmfs_block_read_sb(blk_id,pos,buf,exp_len);
			 break;
								}

								/* Inline in the inode */
		 case VMFS_BLK_TYPE_FD:
			 if (blk_id == f->inode->id) {
				 exp_len = m_min(len,file_size - pos);
				 memcpy(buf, f->inode->content + pos, exp_len);
				 res = exp_len;
				 break;
			 }

		 default:
			 fprintf(stderr,"VMFS: unknown block type 0x%2.2x\n",blk_type);
			 return(-EIO);
		}

		/* Error while reading block, abort immediately */
		if (res < 0)
			return(res);

		/* Move file position and keep track of bytes currently read */
		pos += res;
		rlen += res;

		/* Move buffer position */
		buf += res;
		len -= res;
	}

	return(rlen);
}

/* Read a bitmap header */
int vmfs_bmh_read(vmfs_bitmap_header *bmh,const u_char *buf)
{
	memcpy_s(bmh, sizeof(*bmh), buf, sizeof(*bmh));
	return(0);
}

/* Open a bitmap file */
inline vmfs_bitmap * KernelVMFileSystem::vmfs_bitmap_open_from_file(vmfs_file *f)
{
	DECL_ALIGNED_BUFFER(buf,512);
	vmfs_bitmap *b;

	if (!f)
		return NULL;

	if (vmfs_file_pread(f,buf,buf_len,0) != buf_len) {
		vmfs_file_close(f);
		return NULL;
	}

	if (!(b = (vmfs_bitmap *)calloc(1, sizeof(vmfs_bitmap)))) {
		vmfs_file_close(f);
		return NULL;
	}

	vmfs_bmh_read(&b->bmh, buf);
	b->f = f;
	return b;
}

/* Open a file based on an inode buffer */
vmfs_file *vmfs_file_open_from_inode(vmfs_inode *inode)
{
	vmfs_file *f;

	if (!(f = (vmfs_file *)calloc(1,sizeof(*f))))
		return NULL;

	f->inode = (vmfs_inode *)inode;
	return f;
}

vmfs_bitmap * KernelVMFileSystem::vmfs_bitmap_open_from_inode(vmfs_inode *inode)
{
	return vmfs_bitmap_open_from_file(vmfs_file_open_from_inode(inode));
}


/* Hash function to retrieve an in-core inode */
inline u_int KernelVMFileSystem::vmfs_inode_hash(uint32_t blk_id)
{
	return( (blk_id ^ (blk_id >> 9)) & (inode_hash_buckets - 1) );
}

/* Read a metadata header */
int vmfs_metadata_hdr_read(vmfs_metadata_hdr *mdh,const u_char *buf)
{
	mdh->magic     = read_le32(buf,VMFS_MDH_OFS_MAGIC);
	mdh->pos       = read_le64(buf,VMFS_MDH_OFS_POS);
	mdh->hb_pos    = read_le64(buf,VMFS_MDH_OFS_HB_POS);
	mdh->hb_seq    = read_le64(buf,VMFS_MDH_OFS_HB_SEQ);
	mdh->obj_seq   = read_le64(buf,VMFS_MDH_OFS_OBJ_SEQ);
	mdh->hb_lock   = read_le32(buf,VMFS_MDH_OFS_HB_LOCK);
	mdh->mtime     = read_le64(buf,VMFS_MDH_OFS_MTIME);
	memcpy_s(&mdh->hb_uuid, sizeof(MyUUID), buf + VMFS_MDH_OFS_HB_UUID, sizeof(MyUUID));
	return(0);
}

inline uint32_t vmfs_file_type2mode(uint32_t type) {
	switch (type) {
   case VMFS_FILE_TYPE_DIR:
	   return S_IFDIR;
   case VMFS_FILE_TYPE_SYMLINK:
	   return S_IFLNK;
   default:
	   return S_IFREG;
	}
}


static inline uint32_t vmfs_inode_read_blk_id(const u_char *buf,u_int index)
{
	return(read_le32(buf,VMFS_INODE_OFS_BLK_ARRAY+(index*sizeof(uint32_t))));
}

/* Read an inode */
int vmfs_inode_read(vmfs_inode *inode,u_char *buf)
{
	int i;

	vmfs_metadata_hdr_read(&inode->mdh,buf);

	if (inode->mdh.magic != VMFS_INODE_MAGIC)
		return(-1);

	inode->id        = read_le32(buf,VMFS_INODE_OFS_ID);
	inode->id2       = read_le32(buf,VMFS_INODE_OFS_ID2);
	inode->nlink     = read_le32(buf,VMFS_INODE_OFS_NLINK);
	inode->type      = read_le32(buf,VMFS_INODE_OFS_TYPE);
	inode->flags     = read_le32(buf,VMFS_INODE_OFS_FLAGS);
	inode->size      = read_le64(buf,VMFS_INODE_OFS_SIZE);
	inode->blk_size  = read_le64(buf,VMFS_INODE_OFS_BLK_SIZE);
	inode->blk_count = read_le64(buf,VMFS_INODE_OFS_BLK_COUNT);
	inode->mtime     = read_le32(buf,VMFS_INODE_OFS_MTIME);
	inode->ctime     = read_le32(buf,VMFS_INODE_OFS_CTIME);
	inode->atime     = read_le32(buf,VMFS_INODE_OFS_ATIME);
	inode->uid       = read_le32(buf,VMFS_INODE_OFS_UID);
	inode->gid       = read_le32(buf,VMFS_INODE_OFS_GID);
	inode->mode      = read_le32(buf,VMFS_INODE_OFS_MODE);
	inode->zla       = read_le32(buf,VMFS_INODE_OFS_ZLA);
	inode->tbz       = read_le32(buf,VMFS_INODE_OFS_TBZ);
	inode->cow       = read_le32(buf,VMFS_INODE_OFS_COW);

	/* "corrected" mode */
	inode->cmode    = inode->mode | vmfs_file_type2mode(inode->type);

	if (inode->type == VMFS_FILE_TYPE_RDM) {
		inode->rdm_id = read_le32(buf,VMFS_INODE_OFS_RDM_ID);
	} else if (inode->zla == VMFS5_ZLA_BASE + VMFS_BLK_TYPE_FD) {
		memcpy(inode->content, buf + VMFS_INODE_OFS_CONTENT, inode->size);
	} else {
		for(i=0;i<VMFS_INODE_BLK_COUNT;i++)
			inode->blocks[i] = vmfs_inode_read_blk_id(buf,i);
	}
	return(0);
}

/* Get inode corresponding to a block id */
int KernelVMFileSystem::vmfs_inode_get(uint32_t blk_id,vmfs_inode *inode)
{
	u_char * buf(NULL);
	DECL_ALIGNED_BUFFER_WOL(buf,VMFS_INODE_SIZE);

	if (VMFS_BLK_TYPE(blk_id) != VMFS_BLK_TYPE_FD)
		return(-1);

	if (!vmfs_bitmap_get_item(fdc, VMFS_BLK_FD_ENTRY(blk_id),
		VMFS_BLK_FD_ITEM(blk_id), buf))
		return(-1);
	return(vmfs_inode_read(inode,buf));
}

/* Register an inode in the in-core inode hash table */
void KernelVMFileSystem::vmfs_inode_register(vmfs_inode *inode)
{
	u_int hb;

	hb = vmfs_inode_hash(inode->id);

	inode->ref_count = 1;

	/* Insert into hash table */
	inode->next  = inodes[hb];
	inode->pprev = &(inodes[hb]);

	if (inode->next != NULL)
		inode->next->pprev = &inode->next;

	inodes[hb] = inode;
}

/* Acquire an inode */
vmfs_inode * KernelVMFileSystem::vmfs_inode_acquire(uint32_t blk_id)
{
	vmfs_inode *inode;
	u_int hb;

	hb = vmfs_inode_hash(blk_id);
	for(inode=inodes[hb];inode;inode=inode->next)
		if (inode->id == blk_id) {
			inode->ref_count++;
			return inode;
		}

		/* Inode not yet used, allocate room for it */
		if (!(inode = (vmfs_inode *)calloc(1,sizeof(*inode))))
			return NULL;

		if (vmfs_inode_get(blk_id,inode) == -1) {
			free(inode);
			return NULL;
		}

		vmfs_inode_register(inode);
		return inode;
}

/* Open a file based on a directory entry */
vmfs_file * KernelVMFileSystem::vmfs_file_open_from_blkid(uint32_t blk_id)
{
	vmfs_inode *inode;

	if (!(inode = vmfs_inode_acquire(blk_id)))
		return NULL;

	return(vmfs_file_open_from_inode(inode));
}

/* Open a directory */
vmfs_dir * KernelVMFileSystem::vmfs_dir_open_at(vmfs_dir *d,const char *path)
{
	return vmfs_dir_open_from_file(vmfs_file_open_at(d,path));
}

/* Cache content of a directory */
int KernelVMFileSystem::vmfs_dir_cache_entries(vmfs_dir *d)
{
	off_t dir_size;

	if (d->buf != NULL)
		free(d->buf);

	dir_size = d->dir->GetFileSize();

	if (!(d->buf = (u_char *)calloc(1,dir_size)))
		return(-1);

	if (vmfs_file_pread(d->dir,d->buf,dir_size,0) != dir_size) {
		free(d->buf);
		return(-1);
	}

	return(0);
}

/* Open a directory file */
vmfs_dir * KernelVMFileSystem::vmfs_dir_open_from_file(vmfs_file *file)
{
	vmfs_dir *d;

	if (file == NULL)
		return NULL;

	if (!(d = (vmfs_dir *)calloc(1, sizeof(*d))) ||
		(file->inode->type != VMFS_FILE_TYPE_DIR)) {
			vmfs_file_close(file);
			return NULL;
	}

	d->dir = file;
	vmfs_dir_cache_entries(d);
	return d;
}

/* Set position of the next entry that vmfs_dir_read will return */
inline void vmfs_dir_seek(vmfs_dir *d, uint32_t pos)
{
	if (d)
		d->pos = pos;
}

/* Read a directory entry */
static int vmfs_dirent_read(vmfs_dirent *entry,const u_char *buf)
{
	entry->type      = read_le32(buf,VMFS_DIRENT_OFS_TYPE);
	entry->block_id  = read_le32(buf,VMFS_DIRENT_OFS_BLK_ID);
	entry->record_id = read_le32(buf,VMFS_DIRENT_OFS_REC_ID);
	memcpy(entry->name,buf+VMFS_DIRENT_OFS_NAME,VMFS_DIRENT_OFS_NAME_SIZE);
	entry->name[VMFS_DIRENT_OFS_NAME_SIZE] = 0;
	return(0);
}

/* Return next entry in directory. Returned directory entry will be overwritten
by subsequent calls */
vmfs_dirent * KernelVMFileSystem::vmfs_dir_read(vmfs_dir *d)
{
	u_char *buf;
	if (d == NULL)
		return(NULL);

	if (d->buf) {
		if (d->pos*VMFS_DIRENT_SIZE >= d->dir->GetFileSize())
			return(NULL);
		buf = &d->buf[d->pos*VMFS_DIRENT_SIZE];
	} else {
		u_char _buf[VMFS_DIRENT_SIZE];
		if ((vmfs_file_pread(d->dir,_buf,sizeof(_buf),
			d->pos*sizeof(_buf)) != sizeof(_buf)))
			return(NULL);
		buf = _buf;
	}

	vmfs_dirent_read(&d->dirent,buf);
	d->pos++;

	return &d->dirent;
}

/* Open a directory based on a directory entry */
vmfs_dir * KernelVMFileSystem::vmfs_dir_open_from_blkid(uint32_t blk_id)
{
	return vmfs_dir_open_from_file(vmfs_file_open_from_blkid(blk_id));
}

/* Search for an entry into a directory ; affects position of the next
entry vmfs_dir_read will return */
vmfs_dirent * KernelVMFileSystem::vmfs_dir_lookup(vmfs_dir *d,const char *name)
{
	vmfs_dirent *rec;
	vmfs_dir_seek(d,0);

	while((rec = vmfs_dir_read(d))) {
		if (!strcmp(rec->name,name))
			return(rec);
	}

	return(NULL);
}

/* Read a symlink */
char *KernelVMFileSystem::vmfs_dirent_read_symlink(const vmfs_dirent *entry)
{
	vmfs_file *f;
	size_t str_len;
	char *str = NULL;

	if (!(f = vmfs_file_open_from_blkid(entry->block_id)))
		return NULL;

	str_len = f->GetFileSize();

	if (!(str = (char *)malloc(str_len+1)))
		goto done;

	if ((str_len = vmfs_file_pread(f,(u_char *)str,str_len,0)) == -1) {
		free(str);
		goto done;
	}

	str[str_len] = 0;

done:
	vmfs_file_close(f);
	return str;
}

/* Close a directory */
int vmfs_dir_close(vmfs_dir *d)
{
	if (d == NULL)
		return(-1);

	if (d->buf)
		free(d->buf);

	vmfs_file_close(d->dir);
	free(d);
	return(0);
}


/* Resolve a path name to a block id */
uint32_t KernelVMFileSystem::vmfs_dir_resolve_path(vmfs_dir *base_dir,const char *path,
							   int follow_symlink)
{
	vmfs_dir *cur_dir,*sub_dir;
	const vmfs_dirent *rec;
	char *nam, *ptr,*sl,*symlink;
	int close_dir = 0;
	uint32_t ret = 0;

	cur_dir = base_dir;

	if (*path == '/') {
		if (!(cur_dir = vmfs_dir_open_from_blkid(VMFS_BLK_FD_BUILD(0, 0, 0))))
			return(0);
		path++;
		close_dir = 1;
	}

	if (!(rec = vmfs_dir_lookup(cur_dir,".")))
		return(0);

	ret = rec->block_id;

	nam = ptr = _strdup(path);

	while(*ptr != 0) {
		sl = strchr(ptr,'/');

		if (sl != NULL)
			*sl = 0;

		if (*ptr == 0) {
			ptr = sl + 1;
			continue;
		}

		if (!(rec = vmfs_dir_lookup(cur_dir,ptr))) {
			ret = 0;
			break;
		}

		ret = rec->block_id;

		if ((sl == NULL) && !follow_symlink)
			break;

		/* follow the symlink if we have an entry of this type */
		if (rec->type == VMFS_FILE_TYPE_SYMLINK) {
			if (!(symlink = vmfs_dirent_read_symlink(rec))) {
				ret = 0;
				break;
			}

			ret = vmfs_dir_resolve_path(cur_dir,symlink,1);
			free(symlink);

			if (!ret)
				break;
		}

		/* last token */
		if (sl == NULL)
			break;

		/* we must have a directory here */
		if (!(sub_dir = vmfs_dir_open_from_blkid(ret)))
		{
			ret = 0;
			break;
		}

		if (close_dir)
			vmfs_dir_close(cur_dir);

		cur_dir = sub_dir;
		close_dir = 1;
		ptr = sl + 1;
	}
	free(nam);

	if (close_dir)
		vmfs_dir_close(cur_dir);

	return(ret);
}

/* Open a file */
vmfs_file * KernelVMFileSystem::vmfs_file_open_at(vmfs_dir *dir,const char *path)
{
	uint32_t blk_id;

	if (!(blk_id = vmfs_dir_resolve_path(dir,path,1)))
		return(NULL);

	return(vmfs_file_open_from_blkid(blk_id));
}

vmfs_bitmap * KernelVMFileSystem::vmfs_bitmap_open_at(vmfs_dir *d,const char *name)
{
	return vmfs_bitmap_open_from_file(vmfs_file_open_at(d, name));
}

/* Close a bitmap file */
void vmfs_bitmap_close(vmfs_bitmap *b)
{
	if (b != NULL) {
		vmfs_file_close(b->f);
		free(b);
	}
}

vmfs_bitmap * KernelVMFileSystem::vmfs_open_meta_file(vmfs_dir *root_dir, char *name,
										  uint32_t max_item, uint32_t max_entry,
										  char *desc)
{
	vmfs_bitmap *bitmap = vmfs_bitmap_open_at(root_dir, name);
	if (!bitmap) {
		fprintf(stderr, "Unable to open %s.\n", desc);
		return NULL;
	}

	if (bitmap->bmh.items_per_bitmap_entry > max_item) {
		fprintf(stderr, "Unsupported number of items per entry in %s.\n", desc);
		return NULL;
	}
	if ((bitmap->bmh.total_items + bitmap->bmh.items_per_bitmap_entry - 1) /
		bitmap->bmh.items_per_bitmap_entry > max_entry) {
			fprintf(stderr,"Unsupported number of entries in %s.\n", desc);
			return NULL;
	}
	return bitmap;
}

/* Open all the VMFS meta files */
int KernelVMFileSystem::vmfs_open_all_meta_files()
{
	/* Read the first inode */
	if (!(root_dir = vmfs_dir_open_from_blkid(VMFS_BLK_FD_BUILD(0, 0, 0)))) {
		fprintf(stderr,"VMFS: unable to open root directory\n");
		return(-1);
	}

	if (!(fbb = vmfs_bitmap_open_at(root_dir,VMFS_FBB_FILENAME))) {
		fprintf(stderr,"Unable to open file-block bitmap (FBB).\n");
		return(-1);
	}
	if (fbb->bmh.total_items > VMFS_BLK_FB_MAX_ITEM) {
		fprintf(stderr, "Unsupported number of items in file-block bitmap (FBB).\n");
		return(-1);
	}

	fdc = vmfs_open_meta_file(root_dir, VMFS_FDC_FILENAME,
		VMFS_BLK_FD_MAX_ITEM, VMFS_BLK_FD_MAX_ENTRY,
		"file descriptor bitmap (FDC)");
	if (!fdc)
		return(-1);

	pbc = vmfs_open_meta_file(root_dir, VMFS_PBC_FILENAME,
		VMFS_BLK_PB_MAX_ITEM, VMFS_BLK_PB_MAX_ENTRY,
		"pointer block bitmap (PBC)");
	if (!pbc)
		return(-1);

	sbc = vmfs_open_meta_file(root_dir, VMFS_SBC_FILENAME,
		VMFS_BLK_SB_MAX_ITEM, VMFS_BLK_SB_MAX_ENTRY,
		"pointer block bitmap (PBC)");
	if (!sbc)
		return(-1);
	return(0);
}

int KernelVMFileSystem::vmfs_read_fdc_base()
{
   vmfs_inode inode = { { 0, }, };
   uint32_t fdc_base;

   /* 
    * Compute position of FDC base: it is located at the first
    * block after heartbeat information.
    * When blocksize = 8 Mb, there is free space between heartbeats
    * and FDC.
    */
   fdc_base = m_max(1, (VMFS_HB_BASE + VMFS_HB_NUM * VMFS_HB_SIZE) /
                    fs_info.block_size);

   inode.mdh.magic = VMFS_INODE_MAGIC;
   inode.size = fs_info.block_size;
   inode.type = VMFS_FILE_TYPE_META;
   inode.blk_size = fs_info.block_size;
   inode.blk_count = 1;
   inode.zla = VMFS_BLK_TYPE_FB;
   inode.blocks[0] = VMFS_BLK_FB_BUILD(fdc_base, 0);
   inode.ref_count = 1;

   fdc = vmfs_bitmap_open_from_inode(&inode);

   /* Read the meta files */
   if (vmfs_open_all_meta_files() == -1)
      return(-1);

   return(0);
}

int KernelVMFileSystem::cmd_ls(vmfs_dir *base_dir, char * path)
{
	vmfs_dir *d;
	const vmfs_dirent *entry;
	int long_format=0;

	if (!(d = vmfs_dir_open_at(base_dir, path))) {
		printf("Unable to open directory %s\n", path);
		return(-1);
	}

	while((entry = vmfs_dir_read(d))) {
		printf("%s\n",entry->name);
	}
	vmfs_dir_close(d);
	return(0);
}