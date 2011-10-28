/*
 * fschecker.c
 * 
 * This utility provides basic file system integrity checks.
 *
 * revision history:
 *
 * name            date         version         description
 * B. Jordan       23/9/2011    1.0             created
 */

#include <stdlib.h>
#include <stdio.h>
#include <mhash.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include "types.h"
#include <string.h>

struct file_meta_t get_file_meta(char* fname);
unsigned char *get_file_hash(char* fname);
unsigned char *get_file_hash_hmac(char* fname, const char* key);
unsigned char *get_hash_str(unsigned char *hash);
void write_file_hash(FILE *fp, char *fname, unsigned char *hash, int path_include);
void compare_file_hashes();
void generate_db_hash(const char *key);
int compare_db_hash(const char *key);
void print_file_hash(unsigned char* hash);

int main(int argc, char* argv[]) {

	if (argc != 3) {
		printf("%s","usage: fsc <mode> <pass>\n");
		exit(1);
	}

	char mode = '\0';
	if (strlen(argv[1]) == 1) {
		mode = argv[1][0];
	}

	if ((mode != FSC_MODE_GEN) && (mode != FSC_MODE_CHK)) {
		printf("invalid run mode: %s\n", argv[1]);
		exit(1);
	}

	const char *key = argv[2];

	if (mode == FSC_MODE_GEN) {
		generate_db_hash(key);
	} else if (mode == FSC_MODE_CHK) {

		/* Generate db hash and compare it to stored hash. */
		int status = compare_db_hash(key);
		if (status == INTEGRITY_CHECK_FAIL) {
			printf("error: integrity check failed.\n");	
		} else if (status == INTEGRITY_CHECK_PASS) {

			/* Compare each hash in database to current hash. */
			compare_file_hashes();
		}
	}

	return 0;
}

void generate_db_hash(const char *key) {

	FILE *fp = fopen(FSC_CONFIG_FILENAME, "r");
	unsigned char *hash;
	char buffer[256];
	char *fname = NULL;

	if (fp != NULL) {

		FILE *fp2 = fopen(FSC_FILE_HASH_FILENAME, "w");

		if (fp2 == NULL) {
			fprintf(stderr, "could not open file hash db for writing: %s\n", FSC_FILE_HASH_FILENAME);
			exit(1);
		}

		printf("writing file hashes to db ...\n");		

        	while (1) {
			fgets(buffer, sizeof(buffer), fp);
			fname = strtok(buffer, "\"");
               		if (feof(fp)) break;
                	hash = get_file_hash(fname);
                	write_file_hash(fp2, fname, hash, PATH_INCLUDE);
                	memset(hash, 0, mhash_get_block_size(MHASH_SHA256));
        	}

		fclose(fp2);
        	fclose(fp);
	} else {
        	printf("unable to open config file. Make sure %s exists and is readable.\n", FSC_CONFIG_FILENAME);
	}

	printf("generating db hash ...\n");

	hash = get_file_hash_hmac(FSC_FILE_HASH_FILENAME, (char*)key);

	FILE *fp3 = fopen(FSC_DB_HASH_FILENAME, "w");
	if (fp3 == NULL) {
		printf("could not db hash file for writing: %s\n", FSC_DB_HASH_FILENAME);
		exit(1);
	}

	write_file_hash(fp3, NULL, hash, PATH_NOINCLUDE);

	fclose(fp3);

	printf("generation complete!\n");
}

int compare_db_hash(const char *key) {

	/* open the db hashes file */
	FILE *fp = fopen(FSC_DB_HASH_FILENAME, "r");
	const size_t hash_length = mhash_get_block_size(MHASH_SHA256);
	unsigned char *cmphash = (unsigned char *) malloc(hash_length*2+1);

	if (fp == NULL) {
		printf("unable read db hash: %s\n", FSC_DB_HASH_FILENAME);
		exit(1);
	}

	// TODO

	/* Read the db hash. */
	fscanf(fp, "%s", cmphash);
	fclose(fp);
	
	unsigned char *hash = get_file_hash_hmac(FSC_FILE_HASH_FILENAME, key);

	if (memcmp(cmphash, get_hash_str(hash),hash_length*2+1) == 0) {
		return INTEGRITY_CHECK_PASS;
	} else {
		return INTEGRITY_CHECK_FAIL;
	}
}

void compare_file_hashes() {

	FILE *fp = fopen(FSC_FILE_HASH_FILENAME, "r");
	const size_t hash_length = mhash_get_block_size(MHASH_SHA256);
	unsigned char *hash;	
	char *fname = NULL;
	char *cmphash = NULL;
	char buff[512];

	if (fp == NULL) {
		printf("unable read db hash: %s\n", FSC_DB_HASH_FILENAME);
 		exit(1);
	}

	/* Loop through each line in the file hash database. */
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		fname = strtok(buff, "\"");
		cmphash = strtok(NULL, ":");
		hash = get_file_hash(fname);
		printf("\"%s\" ", fname);
		if (memcmp(cmphash, get_hash_str(hash),hash_length*2) == 0) {
			printf("okay\n");
		} else {
			printf("changed\n");
		}

	}

	fclose(fp);
}

unsigned char *get_hash_str(unsigned char *hash) {

	const char lookup[] = "0123456789abcdef";
	const size_t hash_length = mhash_get_block_size(MHASH_SHA256);
	size_t i;
	unsigned char * out = malloc(hash_length*2+1);

	if(out==NULL)
		return NULL;

	for (i = 0; i < hash_length; i++)
	{
		out[i*2]=lookup[hash[i]>>4];
		out[i*2+1]=lookup[hash[i]&0xf];
	}
	
	out[hash_length*2]=0;

	return out;
}

void print_file_hash(unsigned char *hash) {

	int i;
	for (i = 0; i < mhash_get_block_size(MHASH_SHA256); i++) {
		printf("%.2x", hash[i]);
	}
	printf("\n");
}

void write_file_hash(FILE *fp, char *fname, unsigned char *hash, int path_include) {

	int i;

	if (path_include == PATH_INCLUDE) {
		fprintf(fp, "\"%s\":", fname);
	}

	for (i = 0; i < mhash_get_block_size(MHASH_SHA256); i++) {
        	fprintf(fp, "%.2x", hash[i]);
	}

	fprintf(fp, "\n");
}

unsigned char *get_file_hash_hmac(char *fname, const char *key) { 

	FILE *fp = fopen(fname, "rb");

	if (fp == NULL) {
		printf("could not read file: %s\n", fname);
		exit(1);
	}

	struct file_meta_t file_meta = get_file_meta(fname);
	unsigned char buffer;
	unsigned char *hash;	

	MHASH td = mhash_hmac_init(MHASH_SHA256, (char*)key, strlen(key), mhash_get_hash_pblock(MHASH_SHA256));
	if (td == MHASH_FAILED) exit(1);

	while (fread(&buffer, 1, 1, fp) == 1) {
		mhash(td, &buffer, 1);
	}

	mhash(td, &file_meta, sizeof(struct file_meta_t));

	// TODO: add salt!

	hash = mhash_hmac_end(td);
		
	fclose(fp);

	return hash;
}

// Generates SHA256 hash for the specified file.
unsigned char *get_file_hash(char* fname) {

	FILE *fp = fopen(fname , "rb");

	if (fp == NULL) {
		printf("could not read file: %s\n", fname);
		exit(1);	
	}

	struct file_meta_t file_meta = get_file_meta(fname);
	unsigned char buffer;
	unsigned char *hash;

	MHASH td = mhash_init(MHASH_SHA256);
	if (td == MHASH_FAILED) exit(1);

	while (fread(&buffer, 1, 1, fp) == 1) {
		mhash(td, &buffer, 1);
	}

	mhash(td, &file_meta, sizeof(struct file_meta_t));

	hash = mhash_end(td);

	fclose(fp);

	return hash;
}

// Returns selected metadata from stat structures for the specified file.
// Metadata is preformatted for the purpose of hashing.
struct file_meta_t get_file_meta(char* fname) {

	struct file_meta_t file_meta;
	struct stat buf;

        if (lstat(fname, &buf) < 0) {
                printf("lstat error\n");
        }

	file_meta.mode = buf.st_mode;
	file_meta.uid = buf.st_uid;
	file_meta.gid = buf.st_gid;
	file_meta.inode = buf.st_ino;
	file_meta.fsize = (unsigned long) buf.st_size;
 	snprintf(file_meta.mtime, FSC_UL_LENGTH, "%lu", buf.st_mtime);
	snprintf(file_meta.ctime, FSC_UL_LENGTH, "%lu", buf.st_ctime);
	return file_meta;
}

