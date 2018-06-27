#ifndef __KERNELVMFILESYSTEM_H__
#define __KERNELVMFILESYSTEM_H__
#include "Windows.h"
#include "time.h"
#include "stddef.h"
#include <vector>

using std::vector;

typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef SSIZE_T ssize_t;

#define m_max(a,b) (((a) > (b)) ? (a) : (b))
#define m_min(a,b) (((a) < (b)) ? (a) : (b))

#define M_SECTOR_SIZE  512
#define M_BLK_SIZE     4096

/* 
 * Block size/alignment required for direct I/O : 
 *    4k bytes on Linux 2.4,
 *    512 bytes on Linux 2.6
 */
#define M_DIO_BLK_SIZE  4096

#define ALIGN_CHECK(val, mult)  (((val) & ((mult) - 1)) == 0)
#define ALIGN_NUM(val, mult) (((val) + ((mult) - 1)) & ~(((mult) - 1)))
#define ALIGN_PTR(ptr, mult) (void *)ALIGN_NUM((uintptr_t)(ptr), mult)

#define DECL_ALIGNED_BUFFER(name, size) \
	u_char __##name[(size) + M_SECTOR_SIZE]; \
	u_char *name = (u_char *)ALIGN_PTR(__##name,M_SECTOR_SIZE); \
	size_t name##_len = (size)

inline void DECL_ALIGNED_BUFFER_WOL(u_char * & name, int size)
{
	u_char * __name = new u_char[(size) + M_SECTOR_SIZE];
	name = (u_char *)ALIGN_PTR(__name,M_SECTOR_SIZE);
}

struct MyUUID
{
public:
	byte uuid[16];
};

const uint64_t VMFS_BASE(0x1000000);

/************************************************************************/
/*                              Raw Data                                */
/************************************************************************/

#pragma pack(1)

/* === Volume Info === */
#define VMFS_VOLINFO_BASE   0x100000
#define VMFS_VOLINFO_MAGIC  0xc001d00d

struct vmfs_volinfo_raw {
   uint32_t magic;
   uint32_t ver;
   u_char _unknown0[6];
   u_char lun;
   u_char _unknown1[3];
   char name[28];
   u_char _unknown2[49]; /* The beginning of this array looks like it is a LUN
                          * GUID for 3.31 * filesystems, and the LUN identifier
                          * string as given by ESX for 3.21 filesystems. */
   uint32_t size; /* Size of the physical volume, divided by 256 */
   u_char _unknown3[31];
   MyUUID uuid;
   uint64_t ctime; /* ctime? in usec */
   uint64_t mtime; /* mtime? in usec */
};

#define VMFS_VOLINFO_OFS_MAGIC offsetof(struct vmfs_volinfo_raw, magic)
#define VMFS_VOLINFO_OFS_VER   offsetof(struct vmfs_volinfo_raw, ver)
#define VMFS_VOLINFO_OFS_LUN   offsetof(struct vmfs_volinfo_raw, lun)
#define VMFS_VOLINFO_OFS_NAME  offsetof(struct vmfs_volinfo_raw, name)
#define VMFS_VOLINFO_OFS_SIZE  offsetof(struct vmfs_volinfo_raw, size)
#define VMFS_VOLINFO_OFS_UUID  offsetof(struct vmfs_volinfo_raw, uuid)

#define VMFS_VOLINFO_OFS_NAME_SIZE 28

/* === LVM Info === */
#define VMFS_LVMINFO_OFFSET            0x0200

struct vmfs_lvminfo_raw {
   uint64_t size;
   uint64_t blocks; /* Seems to always be sum(num_segments for all extents) +
                    * num_extents */
   uint32_t _unknown0;
   char uuid_str[35];
   u_char _unknown1[29];
   MyUUID uuid;
   uint32_t _unknown2;
   uint64_t ctime; /* ctime? in usec */
   uint32_t _unknown3;
   uint32_t num_segments;
   uint32_t first_segment;
   uint32_t _unknown4;
   uint32_t last_segment;
   uint32_t _unknown5;
   uint64_t mtime; /* mtime? in usec */
   uint32_t num_extents;
};

#define VMFS_LVMINFO(field) \
	(VMFS_LVMINFO_OFFSET + offsetof(struct vmfs_lvminfo_raw, field))

#define VMFS_LVMINFO_OFS_SIZE          VMFS_LVMINFO(size)
#define VMFS_LVMINFO_OFS_BLKS          VMFS_LVMINFO(blocks)
#define VMFS_LVMINFO_OFS_UUID_STR      VMFS_LVMINFO(uuid_str)
#define VMFS_LVMINFO_OFS_UUID          VMFS_LVMINFO(uuid)
#define VMFS_LVMINFO_OFS_NUM_SEGMENTS  VMFS_LVMINFO(num_segments)
#define VMFS_LVMINFO_OFS_FIRST_SEGMENT VMFS_LVMINFO(first_segment)
#define VMFS_LVMINFO_OFS_LAST_SEGMENT  VMFS_LVMINFO(last_segment)
#define VMFS_LVMINFO_OFS_NUM_EXTENTS   VMFS_LVMINFO(num_extents)

#define VMFS_FSINFO_BASE   0x0200000
#define VMFS_FSINFO_MAGIC  0x2fabf15e

struct vmfs_fsinfo_raw {
	uint32_t magic;
	uint32_t volver;
	u_char ver;
	MyUUID uuid;
	uint32_t mode;
	char label[128];
	uint32_t dev_blocksize;
	uint64_t blocksize;
	uint32_t ctime; /* ctime? in seconds */
	uint32_t _unknown3;
	MyUUID lvm_uuid;
	u_char _unknown4[16];
	uint32_t fdc_header_size;
	uint32_t fdc_bitmap_count;
	uint32_t subblock_size;
};

#define VMFS_FSINFO_OFS_MAGIC    offsetof(struct vmfs_fsinfo_raw, magic)
#define VMFS_FSINFO_OFS_VOLVER   offsetof(struct vmfs_fsinfo_raw, volver)
#define VMFS_FSINFO_OFS_VER      offsetof(struct vmfs_fsinfo_raw, ver)
#define VMFS_FSINFO_OFS_UUID     offsetof(struct vmfs_fsinfo_raw, uuid)
#define VMFS_FSINFO_OFS_MODE     offsetof(struct vmfs_fsinfo_raw, mode)
#define VMFS_FSINFO_OFS_LABEL    offsetof(struct vmfs_fsinfo_raw, label)
#define VMFS_FSINFO_OFS_BLKSIZE  offsetof(struct vmfs_fsinfo_raw, blocksize)
#define VMFS_FSINFO_OFS_CTIME    offsetof(struct vmfs_fsinfo_raw, ctime)
#define VMFS_FSINFO_OFS_LVM_UUID offsetof(struct vmfs_fsinfo_raw, lvm_uuid)
#define VMFS_FSINFO_OFS_SBSIZE   offsetof(struct vmfs_fsinfo_raw, subblock_size)

#define VMFS_FSINFO_OFS_FDC_HEADER_SIZE \
	offsetof(struct vmfs_fsinfo_raw, fdc_header_size)

#define VMFS_FSINFO_OFS_FDC_BITMAP_COUNT \
	offsetof(struct vmfs_fsinfo_raw, fdc_bitmap_count)

#define VMFS_FSINFO_OFS_LABEL_SIZE sizeof(((struct vmfs_fsinfo_raw *)(0))->label)

#define VMFS_HB_BASE  0x0300000

#define VMFS_HB_SIZE  0x200

#define VMFS_HB_NUM   2048

#define VMFS_HB_MAGIC_OFF   0xabcdef01
#define VMFS_HB_MAGIC_ON    0xabcdef02

struct vmfs_heartbeart_raw {
	uint32_t magic;
	uint64_t pos;
	uint64_t seq;
	uint64_t uptime;
	MyUUID uuid;
	uint32_t journal_block;
	uint32_t vol_version;     /* from fs_info (?) */
	uint32_t version;         /* from fs_info (?) */
};

#define VMFS_MDH_OFS_MAGIC    offsetof(struct vmfs_metadata_hdr_raw, magic)
#define VMFS_MDH_OFS_POS      offsetof(struct vmfs_metadata_hdr_raw, pos)
#define VMFS_MDH_OFS_HB_POS   offsetof(struct vmfs_metadata_hdr_raw, hb_pos)
#define VMFS_MDH_OFS_HB_SEQ   offsetof(struct vmfs_metadata_hdr_raw, hb_seq)
#define VMFS_MDH_OFS_OBJ_SEQ  offsetof(struct vmfs_metadata_hdr_raw, obj_seq)
#define VMFS_MDH_OFS_HB_LOCK  offsetof(struct vmfs_metadata_hdr_raw, hb_lock)
#define VMFS_MDH_OFS_HB_UUID  offsetof(struct vmfs_metadata_hdr_raw, hb_uuid)
#define VMFS_MDH_OFS_MTIME    offsetof(struct vmfs_metadata_hdr_raw, mtime)

#define VMFS_METADATA_HDR_SIZE  512

struct vmfs_metadata_hdr_raw {
	uint32_t magic;         /* Magic number */
	uint64_t pos;           /* Position in the volume */
	uint64_t hb_pos;        /* Heartbeat position */
	uint64_t hb_seq;        /* Heartbeat sequence */
	uint64_t obj_seq;       /* Object sequence */
	uint32_t hb_lock;       /* Heartbeat lock flag */
	MyUUID hb_uuid;         /* UUID of locking server */
	uint64_t mtime;
	u_char pad1[0x1c0];     /* Padding/unknown */
};

#define VMFS_INODE_SIZE			0x800
#define VMFS_INODE_BLK_COUNT	0x100

#define VMFS_INODE_MAGIC		0x10c00001

struct vmfs_inode_raw {
	struct vmfs_metadata_hdr_raw mdh;
	uint32_t id;
	uint32_t id2;              /* seems to be VMFS_BLK_FD_ITEM(id) + 1 */
	uint32_t nlink;
	uint32_t type;
	uint32_t flags;
	uint64_t size;
	uint64_t blk_size;
	uint64_t blk_count;
	uint32_t mtime;
	uint32_t ctime;
	uint32_t atime;
	uint32_t uid;
	uint32_t gid;
	uint32_t mode;
	uint32_t zla;
	uint32_t tbz;
	uint32_t cow;
	u_char _unknown2[432];
	union {
		uint32_t blocks[VMFS_INODE_BLK_COUNT];
		uint32_t rdm_id;
		char content[VMFS_INODE_BLK_COUNT * sizeof(uint32_t)];
	};
};

#define VMFS_INODE_OFS_ID         offsetof(struct vmfs_inode_raw, id)
#define VMFS_INODE_OFS_ID2        offsetof(struct vmfs_inode_raw, id2)
#define VMFS_INODE_OFS_NLINK      offsetof(struct vmfs_inode_raw, nlink)
#define VMFS_INODE_OFS_TYPE       offsetof(struct vmfs_inode_raw, type)
#define VMFS_INODE_OFS_FLAGS      offsetof(struct vmfs_inode_raw, flags)
#define VMFS_INODE_OFS_SIZE       offsetof(struct vmfs_inode_raw, size)
#define VMFS_INODE_OFS_BLK_SIZE   offsetof(struct vmfs_inode_raw, blk_size)
#define VMFS_INODE_OFS_BLK_COUNT  offsetof(struct vmfs_inode_raw, blk_count)
#define VMFS_INODE_OFS_MTIME      offsetof(struct vmfs_inode_raw, mtime)
#define VMFS_INODE_OFS_CTIME      offsetof(struct vmfs_inode_raw, ctime)
#define VMFS_INODE_OFS_ATIME      offsetof(struct vmfs_inode_raw, atime)
#define VMFS_INODE_OFS_UID        offsetof(struct vmfs_inode_raw, uid)
#define VMFS_INODE_OFS_GID        offsetof(struct vmfs_inode_raw, gid)
#define VMFS_INODE_OFS_MODE       offsetof(struct vmfs_inode_raw, mode)
#define VMFS_INODE_OFS_ZLA        offsetof(struct vmfs_inode_raw, zla)
#define VMFS_INODE_OFS_TBZ        offsetof(struct vmfs_inode_raw, tbz)
#define VMFS_INODE_OFS_COW        offsetof(struct vmfs_inode_raw, cow)

#define VMFS_INODE_OFS_BLK_ARRAY  offsetof(struct vmfs_inode_raw, blocks)
#define VMFS_INODE_OFS_RDM_ID     offsetof(struct vmfs_inode_raw, rdm_id)
#define VMFS_INODE_OFS_CONTENT    offsetof(struct vmfs_inode_raw, content)

#define VMFS_DIRENT_SIZE    0x8c

struct vmfs_dirent_raw {
	uint32_t type;
	uint32_t block_id;
	uint32_t record_id;
	char name[128];
};

#define VMFS_DIRENT_OFS_TYPE    offsetof(struct vmfs_dirent_raw, type)
#define VMFS_DIRENT_OFS_BLK_ID  offsetof(struct vmfs_dirent_raw, block_id)
#define VMFS_DIRENT_OFS_REC_ID  offsetof(struct vmfs_dirent_raw, record_id)
#define VMFS_DIRENT_OFS_NAME    offsetof(struct vmfs_dirent_raw, name)

#define VMFS_DIRENT_OFS_NAME_SIZE  sizeof(((struct vmfs_dirent_raw *)(0))->name)

/* === Bitmap entry === */
#define VMFS_BITMAP_ENTRY_SIZE    0x400

#define VMFS_BITMAP_BMP_MAX_SIZE  0x1f0

struct vmfs_bitmap_entry_raw {
	struct vmfs_metadata_hdr_raw mdh; /* Metadata header */
	uint32_t id;                      /* Bitmap ID */
	uint32_t total;                   /* Total number of items in this entry */
	uint32_t free;                    /* Free items */
	uint32_t ffree;                   /* First free item */
	uint8_t bitmap[VMFS_BITMAP_BMP_MAX_SIZE];
};

#pragma pack()

/************************************************************************/
/*                             Parsed Data                              */
/************************************************************************/

struct vmfs_volinfo {
	uint32_t magic;
	uint32_t version;
	char * name;
	MyUUID uuid;
	int lun;

	uint32_t size;
	uint64_t lvm_size;
	uint64_t blocks;
	MyUUID lvm_uuid;
	uint32_t num_segments,
		first_segment,
		last_segment,
		num_extents;
};

struct vmfs_fsinfo {
	uint32_t magic;
	uint32_t vol_version;
	uint32_t version;
	uint32_t mode;
	MyUUID uuid;
	char *label;
	time_t ctime;

	uint64_t block_size;
	uint32_t subblock_size;

	uint32_t fdc_header_size;
	uint32_t fdc_bitmap_count;

	MyUUID lvm_uuid;
};

struct vmfs_heartbeat {
	uint32_t magic;
	uint64_t pos;
	uint64_t seq;          /* Sequence number */
	uint64_t uptime;       /* Uptime (in usec) of the locker */
	MyUUID uuid;           /* UUID of the server */
	uint32_t journal_blk;  /* Journal block */
};

struct vmfs_metadata_hdr {
	uint32_t magic;
	uint64_t pos;
	uint64_t hb_pos;
	uint64_t hb_seq;
	uint64_t obj_seq;
	uint32_t hb_lock;
	MyUUID  hb_uuid;
	uint64_t mtime;
};

/* Synchronization flags */
#define VMFS_INODE_SYNC_META  0x01
#define VMFS_INODE_SYNC_BLK   0x02
#define VMFS_INODE_SYNC_ALL   (VMFS_INODE_SYNC_META | VMFS_INODE_SYNC_BLK)

/* Some VMFS 5 features use a weird ZLA */
#define VMFS5_ZLA_BASE 4301

struct vmfs_inode {
	vmfs_metadata_hdr mdh;
	uint32_t id,id2;
	uint32_t nlink;
	uint32_t type;
	uint32_t flags;
	uint64_t size;
	uint64_t blk_size;
	uint64_t blk_count;
	time_t  mtime,ctime,atime;
	uint32_t uid,gid;
	uint32_t mode,cmode;
	uint32_t zla,tbz,cow;
	uint32_t rdm_id;
	union {
		uint32_t blocks[VMFS_INODE_BLK_COUNT];
		char content[VMFS_INODE_BLK_COUNT * sizeof(uint32_t)];
	};

	/* In-core inode information */
	vmfs_inode **pprev,*next;
	u_int ref_count;
	u_int update_flags;
};

/* VMFS meta-files */
#define VMFS_FBB_FILENAME  ".fbb.sf"
#define VMFS_FDC_FILENAME  ".fdc.sf"
#define VMFS_PBC_FILENAME  ".pbc.sf"
#define VMFS_SBC_FILENAME  ".sbc.sf"

/* File types (in inode and directory entries) */
#define VMFS_FILE_TYPE_DIR      0x02
#define VMFS_FILE_TYPE_FILE     0x03
#define VMFS_FILE_TYPE_SYMLINK  0x04
#define VMFS_FILE_TYPE_META     0x05
#define VMFS_FILE_TYPE_RDM      0x06

/* File flags */
#define VMFS_FILE_FLAG_RW  0x01
#define VMFS_FILE_FLAG_FD  0x02

/* === VMFS file abstraction === */
struct vmfs_file {
	union {
		vmfs_inode *inode;
		HANDLE fd;
	};
	u_int flags;
	/* Get file size */
	inline uint64_t GetFileSize()
	{
		return(inode->size);
	}
};

/* Bitmaps magic numbers */
#define VMFS_BITMAP_MAGIC_FBB  0x10c00002
#define VMFS_BITMAP_MAGIC_SBC  0x10c00003
#define VMFS_BITMAP_MAGIC_PBC  0x10c00004
#define VMFS_BITMAP_MAGIC_FDC  0x10c00005

/* === Bitmap header === */
#pragma pack(1)
struct vmfs_bitmap_header {
	uint32_t items_per_bitmap_entry;
	uint32_t bmp_entries_per_area;
	uint32_t hdr_size;
	uint32_t data_size;
	uint32_t area_size;
	uint32_t total_items;
	uint32_t area_count;
};
#pragma pack()

struct vmfs_bitmap_entry {
	vmfs_metadata_hdr mdh;
	uint32_t id;
	uint32_t total;
	uint32_t free;
	uint32_t ffree;
	uint8_t bitmap[VMFS_BITMAP_BMP_MAX_SIZE];
};

/* A bitmap file instance */
struct vmfs_bitmap {
	vmfs_file *f;
	vmfs_bitmap_header bmh;
};


struct vmfs_dirent {
	uint32_t type;
	uint32_t block_id;
	uint32_t record_id;
	char name[129];
};

struct vmfs_dir {
	vmfs_file *dir;
	uint32_t pos;
	vmfs_dirent dirent;
	u_char *buf;
};

/* Block types */
enum vmfs_block_type {
	VMFS_BLK_TYPE_NONE = 0,
	VMFS_BLK_TYPE_FB,     /* File Block */
	VMFS_BLK_TYPE_SB,     /* Sub-Block */
	VMFS_BLK_TYPE_PB,     /* Pointer Block */
	VMFS_BLK_TYPE_FD,     /* File Descriptor */
	VMFS_BLK_TYPE_MAX,
};

__inline int __builtin_ctz(int v)
{
	if (v == 0)
		return 0;

	__asm
	{
		bsf eax, dword ptr[v];
	}
}

#define VMFS_BLK_SHIFT(mask) __builtin_ctz(mask)
#define VMFS_BLK_VALUE(blk_id, mask) (((blk_id) & (mask)) >> VMFS_BLK_SHIFT(mask))
#define VMFS_BLK_MAX_VALUE(mask) (((mask) >> VMFS_BLK_SHIFT(mask)) + 1)
#define VMFS_BLK_FILL(value, mask) (((value) << VMFS_BLK_SHIFT(mask)) & (mask))

#define VMFS_BLK_TYPE_MASK  0x00000007

/* Extract block type from a block ID */
#define VMFS_BLK_TYPE(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_TYPE_MASK)

/* File-Block
 * { unsigned int item:26;
 *   unsigned int flags:3;
 *   unsigned int type:3; }
 * There is probably really no more than one flag, but so far, nothing
 * indicates what can be stored between the significant bits for the block
 * type and the TBZ flag, so we'll consider they are flags of some sort,
 * and will display them as such.
 */
#define VMFS_BLK_FB_ITEM_MASK  0xffffffc0
#define VMFS_BLK_FB_FLAGS_MASK 0x00000038

/* TBZ flag specifies if the block must be zeroed. */
#define VMFS_BLK_FB_TBZ_FLAG    4

#define VMFS_BLK_FB_ITEM(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_FB_ITEM_MASK)
#define VMFS_BLK_FB_FLAGS(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_FB_FLAGS_MASK)

#define VMFS_BLK_FB_MAX_ITEM VMFS_BLK_MAX_VALUE(VMFS_BLK_FB_ITEM_MASK)

#define VMFS_BLK_FB_TBZ(blk_id) \
   (VMFS_BLK_FB_FLAGS(blk_id) & VMFS_BLK_FB_TBZ_FLAG)

#define VMFS_BLK_FB_TBZ_CLEAR(blk_id) ((blk_id) & ~(VMFS_BLK_FILL(VMFS_BLK_FB_TBZ_FLAG, VMFS_BLK_FB_FLAGS_MASK)))

#define VMFS_BLK_FB_BUILD(item, flags) \
   (VMFS_BLK_FILL(item, VMFS_BLK_FB_ITEM_MASK) | \
    VMFS_BLK_FILL(flags, VMFS_BLK_FB_FLAGS_MASK) | \
    VMFS_BLK_TYPE_FB)

/* Sub-Block
 * { unsigned int item_lsb:4;
 *   unsigned int entry:22;
 *   unsigned int flags:1; // Not sure it even exists
 *   unsigned int item_msb: 2;
 *   unsigned int type:3; }
 */
#define VMFS_BLK_SB_ITEM_LSB_MASK 0xf0000000
#define VMFS_BLK_SB_ENTRY_MASK    0x0fffffc0
#define VMFS_BLK_SB_FLAGS_MASK    0x00000020
#define VMFS_BLK_SB_ITEM_MSB_MASK 0x00000018

#define VMFS_BLK_SB_ITEM_VALUE_LSB_MASK 0x0000000f
#define VMFS_BLK_SB_ITEM_VALUE_MSB_MASK 0x00000030

#define VMFS_BLK_SB_ITEM(blk_id) \
   (VMFS_BLK_FILL(VMFS_BLK_VALUE(blk_id, VMFS_BLK_SB_ITEM_LSB_MASK), VMFS_BLK_SB_ITEM_VALUE_LSB_MASK) | \
    VMFS_BLK_FILL(VMFS_BLK_VALUE(blk_id, VMFS_BLK_SB_ITEM_MSB_MASK), VMFS_BLK_SB_ITEM_VALUE_MSB_MASK))
#define VMFS_BLK_SB_ENTRY(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_SB_ENTRY_MASK)
#define VMFS_BLK_SB_FLAGS(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_SB_FLAGS_MASK)

#define VMFS_BLK_SB_MAX_ITEM VMFS_BLK_MAX_VALUE(VMFS_BLK_SB_ITEM_VALUE_LSB_MASK | VMFS_BLK_SB_ITEM_VALUE_MSB_MASK)
#define VMFS_BLK_SB_MAX_ENTRY VMFS_BLK_MAX_VALUE(VMFS_BLK_SB_ENTRY_MASK)

#define VMFS_BLK_SB_BUILD(entry, item, flags) \
   (VMFS_BLK_FILL(entry, VMFS_BLK_SB_ENTRY_MASK) | \
    VMFS_BLK_FILL(VMFS_BLK_VALUE(item, VMFS_BLK_SB_ITEM_VALUE_LSB_MASK), \
                  VMFS_BLK_SB_ITEM_LSB_MASK) | \
    VMFS_BLK_FILL(VMFS_BLK_VALUE(item, VMFS_BLK_SB_ITEM_VALUE_MSB_MASK), \
                  VMFS_BLK_SB_ITEM_MSB_MASK) | \
    VMFS_BLK_FILL(flags, VMFS_BLK_SB_FLAGS_MASK) | \
    VMFS_BLK_TYPE_SB)

/* Pointer-Block
 * { unsigned int item:4;
 *   unsigned int entry:22;
 *   unsigned int flags:3;
 *   unsigned int type:3; }
 */
#define VMFS_BLK_PB_ITEM_MASK  0xf0000000
#define VMFS_BLK_PB_ENTRY_MASK 0x0fffffc0
#define VMFS_BLK_PB_FLAGS_MASK 0x00000038

#define VMFS_BLK_PB_ITEM(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_PB_ITEM_MASK)
#define VMFS_BLK_PB_ENTRY(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_PB_ENTRY_MASK)
#define VMFS_BLK_PB_FLAGS(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_PB_FLAGS_MASK)

#define VMFS_BLK_PB_MAX_ITEM VMFS_BLK_MAX_VALUE(VMFS_BLK_PB_ITEM_MASK)
#define VMFS_BLK_PB_MAX_ENTRY VMFS_BLK_MAX_VALUE(VMFS_BLK_PB_ENTRY_MASK)

#define VMFS_BLK_PB_BUILD(entry, item, flags) \
   (VMFS_BLK_FILL(entry, VMFS_BLK_PB_ENTRY_MASK) | \
    VMFS_BLK_FILL(item, VMFS_BLK_PB_ITEM_MASK) | \
    VMFS_BLK_FILL(flags, VMFS_BLK_PB_FLAGS_MASK) | \
    VMFS_BLK_TYPE_PB)

/* File Descriptor
 * { unsigned int item:10;
 *   unsigned int entry:16;
 *   unsigned int flags:3;
 *   unsigned int type:3; }
 */
#define VMFS_BLK_FD_ITEM_MASK  0xffc00000
#define VMFS_BLK_FD_ENTRY_MASK 0x003fffc0
#define VMFS_BLK_FD_FLAGS_MASK 0x00000038

#define VMFS_BLK_FD_ITEM(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_FD_ITEM_MASK)
#define VMFS_BLK_FD_ENTRY(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_FD_ENTRY_MASK)
#define VMFS_BLK_FD_FLAGS(blk_id) VMFS_BLK_VALUE(blk_id, VMFS_BLK_FD_FLAGS_MASK)

#define VMFS_BLK_FD_MAX_ITEM VMFS_BLK_MAX_VALUE(VMFS_BLK_FD_ITEM_MASK)
#define VMFS_BLK_FD_MAX_ENTRY VMFS_BLK_MAX_VALUE(VMFS_BLK_FD_ENTRY_MASK)

#define VMFS_BLK_FD_BUILD(entry, item, flags) \
   (VMFS_BLK_FILL(entry, VMFS_BLK_FD_ENTRY_MASK) | \
    VMFS_BLK_FILL(item, VMFS_BLK_FD_ITEM_MASK) | \
    VMFS_BLK_FILL(flags, VMFS_BLK_FD_FLAGS_MASK) | \
    VMFS_BLK_TYPE_FD)

struct vmfs_block_info {
	uint32_t entry, item, flags;
	enum vmfs_block_type type;
};

/* === VMFS filesystem === */
#define VMFS_INODE_HASH_BUCKETS  256

class KernelVMFileSystem
{
public:
	KernelVMFileSystem();
	KernelVMFileSystem(HANDLE hDisk);
	~KernelVMFileSystem();
	ssize_t vmfs_file_pread(vmfs_file *f,u_char *buf,size_t len,off_t pos);

	int vmfs_inode_get_block(const vmfs_inode *inode,off_t pos,uint32_t *blk_id);
	ssize_t vmfs_block_read_fb(uint32_t blk_id,off_t pos, u_char *buf,size_t len);
	ssize_t vmfs_block_read_sb(uint32_t blk_id,off_t pos, u_char *buf,size_t len);
	
	inline u_int vmfs_bitmap_get_items_per_area(const vmfs_bitmap_header *bmh);
	off_t vmfs_bitmap_get_item_pos(vmfs_bitmap *b,uint32_t entry,uint32_t item);
	bool vmfs_bitmap_get_item(vmfs_bitmap *b, uint32_t entry, uint32_t item, u_char *buf);
	vmfs_bitmap * vmfs_bitmap_open_from_inode(vmfs_inode *inode);
	inline vmfs_bitmap * vmfs_bitmap_open_from_file(vmfs_file *f);

	int vmfs_read_fdc_base();

	ssize_t vmfs_fs_read(uint32_t blk,off_t offset, u_char *buf,size_t len);
	int vmfs_open_all_meta_files();
	vmfs_dir * vmfs_dir_open_from_blkid(uint32_t blk_id);
	vmfs_file * vmfs_file_open_from_blkid(uint32_t blk_id);
	vmfs_inode * vmfs_inode_acquire(uint32_t blk_id);
	inline u_int vmfs_inode_hash(uint32_t blk_id);

	int vmfs_inode_get(uint32_t blk_id,vmfs_inode *inode);
	void vmfs_inode_register(vmfs_inode *inode);
	int vmfs_dir_cache_entries(vmfs_dir *d);
	vmfs_dir * vmfs_dir_open_from_file(vmfs_file *file);
	vmfs_dirent * vmfs_dir_lookup(vmfs_dir *d,const char *name);
	vmfs_dirent * vmfs_dir_read(vmfs_dir *d);
	char *vmfs_dirent_read_symlink(const vmfs_dirent *entry);
	uint32_t vmfs_dir_resolve_path(vmfs_dir *base_dir,const char *path, int follow_symlink);
	vmfs_file * vmfs_file_open_at(vmfs_dir *dir,const char *path);
	vmfs_bitmap * vmfs_bitmap_open_at(vmfs_dir *d,const char *name);

	vmfs_bitmap * vmfs_open_meta_file(vmfs_dir *root_dir, char *name,
		uint32_t max_item, uint32_t max_entry,
		char *desc);
	vmfs_dir * vmfs_dir_open_at(vmfs_dir *d,const char *path);
	int cmd_ls(vmfs_dir *base_dir, char * path);


	int vmfs_volinfo_read();
	int vmfs_fsinfo_read();

	vmfs_dir * root_dir;

private:

	int debug_level;

	vmfs_volinfo vol_info;

	/* FS information */
	vmfs_fsinfo fs_info;

	/* Associated VMFS Device */
	HANDLE device;

	/* Meta-files containing file system structures */
	vmfs_bitmap *fbb,*sbc,*pbc,*fdc;

	/* Heartbeat used to lock meta-data */
	vmfs_heartbeat hb;
	u_int hb_id;
	uint64_t hb_seq;
	u_int hb_refcount;
	uint64_t hb_expire;

	/* Counter for "gen" field in inodes */
	uint32_t inode_gen;

	/* In-core inodes hash table */
	u_int inode_hash_buckets;
	vmfs_inode **inodes;
};

#endif