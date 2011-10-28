#ifndef FSC_TYPES
#define FSC_TYPES

/* modes */
#define FSC_MODE_GEN 'g'
#define FSC_MODE_CHK 'c'

/* default file names */
#define FSC_FILE_HASH_FILENAME "filedb"
#define FSC_CONFIG_FILENAME "config"
#define FSC_DB_HASH_FILENAME "hashdb"

#define PATH_NOINCLUDE 0
#define PATH_INCLUDE 1

#define INTEGRITY_CHECK_PASS 0
#define INTEGRITY_CHECK_FAIL 1

#define FSC_UL_LENGTH 16

struct file_meta_t {
        int mode;
        int uid;
        int gid;
	int inode;
        unsigned long fsize;
        char mtime[FSC_UL_LENGTH];
	char ctime[FSC_UL_LENGTH];
};

#endif
