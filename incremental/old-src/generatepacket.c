/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003 by Solar Designer
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

/*
 *
 * inc_key_loop() 
 * - new arg: int *num_cache
 * - new var: int first_run
 * - code dealing with the key buffer eliminated
 *
 *
 *
 *
 *
 */


#define TJOHN_CHARSET_PATH "/opt/distributedcracking.net/backend/incremental/"
//#define TJOHN_CHARSET_PATH ""

typedef struct{
        int min_length;
        int max_length;
        int max_count;
        char *file;
}t_ch;

t_ch charsetinfo[] = { 
	// min length, max length, character count, path
	{ 0, 8, 95, TJOHN_CHARSET_PATH "all.chr" },
	{ 1, 8, 26, TJOHN_CHARSET_PATH "alpha.chr" },
	{ 1, 8, 10, TJOHN_CHARSET_PATH "digits.chr" },
	{ 0, 7, 69, TJOHN_CHARSET_PATH "lanman.chr" }
};

unsigned long long rec_num_words;
static unsigned long long num_gen = 0;



// From params.h
// ========================================================================
/*
 * Charset parameters.
 * Be careful if you change these, ((SIZE ** LENGTH) * SCALE) should fit
 * into 64 bits.  You can reduce the SCALE if required.
 */
#define CHARSET_MIN                     ' '
#define CHARSET_MAX                     0x7E
#define CHARSET_SIZE                    (CHARSET_MAX - CHARSET_MIN + 1)
#define CHARSET_LENGTH                  8
#define CHARSET_SCALE                   0x100

/*
 * Charset file format version string.
 */
#define CHARSET_V1                      "CHR1"
#define CHARSET_V2                      "CHR2"
#define CHARSET_V                       CHARSET_V2

/*
 * Buffer size for plaintext passwords.
 */
#define PLAINTEXT_BUFFER_SIZE           0x80



// Everything but the Alpha architechture
// From x86*.h
// ========================================================================
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))




// From charset.h
// ========================================================================
/*
 * Charset file control char codes (only CHARSET_ESC is reserved, and can't
 * be used in a charset).
 */
#define CHARSET_ESC			0
#define CHARSET_NEW			1
#define CHARSET_LINE			2

/*
 * Charset file header.
 */
struct charset_header {
/* CHARSET_V* */
	char version[4];

/* A checksum of the file or equivalent plus some space for future extensions
 * (only 4 bytes are used currently) */
	unsigned char check[24];

/* CHARSET_MIN, CHARSET_MAX */
	unsigned char min, max;

/* CHARSET_LENGTH */
	unsigned char length;

/* Number of different characters, up to (max - min + 1) */
	unsigned char count;

/* File offsets for each length, 32-bit little endian */
	unsigned char offsets[CHARSET_LENGTH][4];

/*
 * Cracking order.
 *
 * This is a list of current {length, fixed position, character count}.
 * There are CHARSET_LENGTH different lengths, and fixed position is up
 * to the current length, which means we have exactly (CHARSET_LENGTH *
 * (CHARSET_LENGTH + 1) / 2) different {length, fixed position} pairs;
 * for each such pair we need to try all charsets from 1 character and
 * up to CHARSET_SIZE characters large.
 */
	unsigned char order
		[CHARSET_LENGTH * (CHARSET_LENGTH + 1) / 2 * CHARSET_SIZE * 3];
};

/*
 * Reads a charset file header.
 */
void charset_read_header(FILE *file, struct charset_header *header);



// From charset.c
// ========================================================================
void charset_read_header(FILE *file, struct charset_header *header)
{
	fread(header->version, sizeof(header->version), 1, file);
	if (memcmp(header->version, CHARSET_V1, sizeof(header->version)))
		fread(header->check, sizeof(header->check), 1, file);
	else
		memset(header->check, 0, sizeof(header->check));
	header->min = getc(file);
	header->max = getc(file);
	header->length = getc(file);
	header->count = getc(file);
	fread(header->offsets, sizeof(header->offsets), 1, file);
	fread(header->order, sizeof(header->order), 1, file);
}





// The topmost part of inc.c
// ========================================================================
extern struct fmt_main fmt_LM;
extern struct fmt_main fmt_NETLM;
extern struct fmt_main fmt_NETHALFLM;

typedef char (*char2_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1];
typedef char (*chars_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1][CHARSET_SIZE + 1];

static int rec_compat;
static int rec_entry;
static int rec_numbers[CHARSET_LENGTH];

static int entry;
static int numbers[CHARSET_LENGTH];

static void inc_format_error(char *charset)
{
	fprintf(stderr, "Incorrect charset file format: %s\n", charset);
	exit(EXIT_FAILURE);
}

static int is_mixedcase(char *chars)
{
	char present[CHARSET_SIZE];
	char *ptr, c;
	unsigned int i;

	memset(present, 0, sizeof(present));
	ptr = chars;
	while ((c = *ptr++)) {
		i = ARCH_INDEX(c) - CHARSET_MIN;
		if (i >= CHARSET_SIZE)
			return -1;
		present[i] = 1;
	}

	ptr = chars;
	while ((c = *ptr++)) {
		/* assume ASCII */
		if (c >= 'A' && c <= 'Z') {
			i = ARCH_INDEX(c | 0x20) - CHARSET_MIN;
			if (i < CHARSET_SIZE && present[i])
				return 1;
		}
	}

	return 0;
}

static void inc_new_length(unsigned int length,
	struct charset_header *header, FILE *file, char *charset,
	char *char1, char2_table char2, chars_table *chars)
{
	long offset;
	int value, pos, i, j;
	char *buffer;
	int count;

	char1[0] = 0;
	if (length)
		memset(char2, 0, sizeof(*char2));
	for (pos = 0; pos <= (int)length - 2; pos++)
		memset(chars[pos], 0, sizeof(**chars));

	offset =
		(long)header->offsets[length][0] |
		((long)header->offsets[length][1] << 8) |
		((long)header->offsets[length][2] << 16) |
		((long)header->offsets[length][3] << 24);
	if (fseek(file, offset, SEEK_SET)) {
		fprintf(stderr, "error: fseek\n");
		exit(EXIT_FAILURE);
	}

	i = j = pos = -1;
	if ((value = getc(file)) != EOF)
	do {
		if (value != CHARSET_ESC) {
			switch (pos) {
			case -1:
				inc_format_error(charset);

			case 0:
				buffer = char1;
				break;

			case 1:
				if (j < 0)
					inc_format_error(charset);
				buffer = (*char2)[j];
				break;

			default:
				if (i < 0 || j < 0)
					inc_format_error(charset);
				buffer = (*chars[pos - 2])[i][j];
			}

			buffer[count = 0] = value;
			while ((value = getc(file)) != EOF) {
				buffer[++count] = value;
				if (value == CHARSET_ESC) break;
				if (count >= CHARSET_SIZE)
					inc_format_error(charset);
			}
			buffer[count] = 0;

			continue;
		}

		if ((value = getc(file)) == EOF) break; else
		if (value == CHARSET_NEW) {
			if ((value = getc(file)) != (int)length) break;
			if ((value = getc(file)) == EOF) break;
			if (value < 0 || value > length)
				inc_format_error(charset);
			pos = value;
		} else
		if (value == CHARSET_LINE) {
			if (pos < 0)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF) break;
			i = value;
			if (i < 0 || i > CHARSET_SIZE)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF) break;
			j = value;
			if (j < 0 || j > CHARSET_SIZE)
				inc_format_error(charset);
		} else
			inc_format_error(charset);

		value = getc(file);
	} while (value != EOF);

	if (value == EOF) {
		if (ferror(file)) {
			fprintf(stderr, "error: getc\n");
			exit(EXIT_FAILURE);
		}
		else
			inc_format_error(charset);
	}
}

static int expand(char *dst, char *src, int size)
{
	char present[CHARSET_SIZE];
	char *dptr = dst, *sptr = src;
	int count = size;
	unsigned int i;

	memset(present, 0, sizeof(present));
	while (*dptr) {
		if (--count <= 1)
			return 0;
		i = ARCH_INDEX(*dptr++) - CHARSET_MIN;
		if (i >= CHARSET_SIZE)
			return -1;
		present[i] = 1;
	}

	while (*sptr) {
		i = ARCH_INDEX(*sptr) - CHARSET_MIN;
		if (i >= CHARSET_SIZE)
			return -1;
		if (!present[i]) {
			*dptr++ = *sptr++;
			if (--count <= 1) break;
		} else
			sptr++;
	}
	*dptr = 0;

	return 0;
}

static void inc_new_count(unsigned int length, int count, char *charset,
	char *allchars, char *char1, char2_table char2, chars_table *chars)
{
	int pos, i, j;
	int size;
	int error;

#if 0
	log_event("- Expanding tables for length %d to character count %d",
		length + 1, count + 1);
#endif

	size = count + 2;

	error = expand(char1, allchars, size);
	if (length)
		error |= expand((*char2)[CHARSET_SIZE], allchars, size);
	for (pos = 0; pos <= (int)length - 2; pos++)
		error |= expand((*chars[pos])[CHARSET_SIZE][CHARSET_SIZE],
			allchars, size);

	for (i = 0; i < CHARSET_SIZE; i++) {
		if (length) error |=
			expand((*char2)[i], (*char2)[CHARSET_SIZE], size);

		for (j = 0; j < CHARSET_SIZE; j++)
		for (pos = 0; pos <= (int)length - 2; pos++) {
			error |= expand((*chars[pos])[i][j], (*chars[pos])
				[CHARSET_SIZE][j], size);
			error |= expand((*chars[pos])[i][j], (*chars[pos])
				[CHARSET_SIZE][CHARSET_SIZE], size);
		}
	}

	if (error)
		inc_format_error(charset);
}

static int inc_key_loop(int length, int fixed, int count,
	char *char1, char2_table char2, chars_table *chars, int *num_cache)
{
	char key_i[PLAINTEXT_BUFFER_SIZE];
	char key_e[PLAINTEXT_BUFFER_SIZE];
	char *key;
	char *chars_cache;
	int numbers_cache;
	int pos;

	// DistributedCracking.net
	int first_run = 1;

#define OFF 1
#if OFF	// DistributedCracking.net
	key_i[length + 1] = 0;
#endif
	numbers[fixed] = count;

	chars_cache = NULL;

update_all:
#if OFF	// DistributedCracking.net
	pos = 0;
#endif
update_ending:

	// DistributedCracking.net: Block added
	if(first_run && num_cache) {
		numbers_cache = *num_cache;	
		first_run = 0;
	}
	else
		numbers_cache = numbers[length];


#if OFF	// DistributedCracking.net
	if (pos < 2) {
		if (pos == 0)
			key_i[0] = char1[numbers[0]];
		if (length) key_i[1] = (*char2)
			[ARCH_INDEX(key_i[0]) - CHARSET_MIN][numbers[1]];
		pos = 2;
	}
	while (pos < length) {

		key_i[pos] = (*chars[pos - 2])
			[ARCH_INDEX(key_i[pos - 2]) - CHARSET_MIN]
			[ARCH_INDEX(key_i[pos - 1]) - CHARSET_MIN]
			[numbers[pos]];
		pos++;
	}
#endif
	numbers_cache = numbers[length];
	if (pos == length) {
		chars_cache = (*chars[pos - 2])
			[ARCH_INDEX(key_i[pos - 2]) - CHARSET_MIN]
			[ARCH_INDEX(key_i[pos - 1]) - CHARSET_MIN];
update_last:
#if OFF	// DistributedCracking.net
		key_i[length] = chars_cache[numbers_cache];
printf("key=%s\n", key_i);
#endif
		// DistributedCracking.net: New block to keep track of generated words
		if( (num_gen ++) >= rec_num_words ){
			if( num_cache )
				*num_cache = numbers_cache;
			return 2;
		}

	}

#if 0	// DistributedCracking.net
	key = key_i;


	if (!ext_mode || !f_filter || ext_filter_body(key_i, key = key_e))
	if (crk_process_key(key)) return 1;
#endif

	if (rec_compat) goto compat;

	pos = length;
	if (fixed < length) {
		if (++numbers_cache <= count) {
			if (length >= 2) goto update_last;
			numbers[length] = numbers_cache;
			goto update_ending;
		}
		numbers[pos--] = 0;
		while (pos > fixed) {
			if (++numbers[pos] <= count) goto update_ending;
			numbers[pos--] = 0;
		}
	}
	while (pos-- > 0) {
		if (++numbers[pos] < count) goto update_ending;
		numbers[pos] = 0;
	}

	return 0;

compat:
	pos = 0;
	if (fixed) {
		if (++numbers[0] < count) goto update_all;
		if (!length && numbers[0] <= count) goto update_all;
		numbers[0] = 0;
		pos = 1;
		while (pos < fixed) {
			if (++numbers[pos] < count) goto update_all;
			numbers[pos++] = 0;
		}
	}
	while (++pos <= length) {
		if (++numbers[pos] <= count) goto update_all;
		numbers[pos] = 0;
	}

	return 0;
}




// Driver code, based on do_incremental_crack()
int main(int argc, char *argv[]) {
	// DistributedCracking.net: Code added
	t_ch *charset;
	int num_cache;
	
	// From inc.c: do_incremental_crack()
	int min_length, max_length, max_count;
	char *extra;
	FILE *file;
	struct charset_header *header;
	unsigned int check;
	char allchars[CHARSET_SIZE + 1];
	char char1[CHARSET_SIZE + 1];
	char2_table char2;
	chars_table chars[CHARSET_LENGTH - 2];
	unsigned char *ptr;
	unsigned int length, fixed, count;
	unsigned int real_count;
	int last_length, last_count;
	int pos;

/*	
	int min_length, max_length = 8, max_count = 95;
	FILE *file;
	struct charset_header *header;
	char allchars[CHARSET_SIZE + 1];
	char char1[CHARSET_SIZE + 1];
	char2_table char2;
	chars_table chars[CHARSET_LENGTH - 2];
	unsigned char *ptr;
	unsigned int length, fixed, count;
	unsigned int real_count;
	int last_length, last_count;
	int num_cache;
	int pos;
*/

	// DistributedCracking.net: Code added
	if( argc != 4 ){
		printf("Usage:\n"
			"%s <charset> <packet info>,<packet values> <packet size>\n"
			"\tThis program is used to generate new packet values for tjohn\n"
			"\t<charset>       -  all/alpha/digits/lanman\n"
			"\t<packet info>   -  charset entry,word length,numbers cache\n"
			"\t<packet values> -  'length' number of values, separated by ','\n"
			"\t<packet size>   -  self explanatory\n", argv[0]);
		return -1;
	}

	if( ! strcmp(argv[1], "all") )
		charset = &charsetinfo[0];
	else if( ! strcmp(argv[1], "alpha") )
		charset = &charsetinfo[1];
	else if( ! strcmp(argv[1], "digits") )
		charset = &charsetinfo[2];
	else if( ! strcmp(argv[1], "lanman") )
		charset = &charsetinfo[3];
	else if( ! strcmp(argv[1], "vms") )
		charset = &charsetinfo[4];
	else {
		fprintf(stderr,"Illegal value for charset!\n");
		return -1;
	}


	// The code below is basically what do_incremental_crack()
	// does but modified to fit outside John the Ripper
	min_length = charset->min_length;
	max_length = charset->max_length;
	max_count = charset->max_count;

	if (!(file = fopen(charset->file, "rb"))){
		fprintf(stderr,"Cannot open file '%s': %s\n", charset->file, strerror(errno));
		exit(-2);
	}

	header = (struct charset_header *)malloc(sizeof(*header));
	charset_read_header(file, header);
	if (ferror(file)) {
		fprintf(stderr, "error: fread\n");
		exit(EXIT_FAILURE);
	}

	if (feof(file) ||
	    (memcmp(header->version, CHARSET_V1, sizeof(header->version)) &&
	    memcmp(header->version, CHARSET_V2, sizeof(header->version))) ||
	    !header->count)
		inc_format_error(charset->file);

	if (header->min != CHARSET_MIN || header->max != CHARSET_MAX ||
	    header->length != CHARSET_LENGTH) {
		fprintf(stderr, "Incompatible charset file: %s\n", charset);
		exit(EXIT_FAILURE);
	}

	if (header->count > CHARSET_SIZE)
		inc_format_error(charset->file);

	check =
		(unsigned int)header->check[0] |
		((unsigned int)header->check[1] << 8) |
		((unsigned int)header->check[2] << 16) |
		((unsigned int)header->check[3] << 24);

	fread(allchars, header->count, 1, file);
	if (ferror(file)) { 
		fprintf(stderr, "error: fread\n");
		exit(EXIT_FAILURE);
	}
	if (feof(file)) inc_format_error(charset->file);

	allchars[header->count] = 0;
	if (expand(allchars, extra ? extra : "", sizeof(allchars)))
		inc_format_error(charset->file);
	real_count = strlen(allchars);

	if (max_count < 0) max_count = CHARSET_SIZE;

#if 0
	if (min_length != max_length)
		log_event("- Lengths %d to %d, up to %d different characters",
			min_length, max_length, max_count);
	else
		log_event("- Length %d, up to %d different characters",
			min_length, max_count);
#endif

	if ((unsigned int)max_count > real_count) {
#if 0
		log_event("! Only %u characters available", real_count);
#endif
		fprintf(stderr, "Warning: only %u characters available\n",
			real_count);
	}
	
	
	
	if (header->length >= 2)
		char2 = (char2_table)malloc(sizeof(*char2));
	else
		char2 = NULL;
	for (pos = 0; pos < (int)header->length - 2; pos++)
		chars[pos] = (chars_table)malloc(sizeof(*chars[0]));

	rec_compat = 0;
	rec_entry = 0;
	memset(rec_numbers, 0, sizeof(rec_numbers));

	if( sscanf(argv[2], "%d,%d,%d", &rec_entry, &length, &num_cache) != 3 ){
		fprintf(stderr,"Illegal packet-info field v1!\n");
		fclose(file); free(header);
		return -1;
	}
		
	if((ptr = (unsigned char *)strchr(argv[2], ',')) == NULL 
		|| (ptr = (unsigned char *)strchr((char *)ptr, ',')) == NULL
		|| (ptr = (unsigned char *)strchr((char *)ptr, ',')) == NULL) {

		fprintf(stderr,"Illegal packet-info field!\n");
		fclose(file); free(header);
		return -1;
	}
	ptr++;
	for(pos=0;pos<length;pos++){
		rec_numbers[pos] = strtol((char *)ptr, NULL, 10);
		ptr = (unsigned char *)strstr((char *)ptr, ","); ptr++;

		if( rec_numbers[pos] >= CHARSET_SIZE ){
			printf("Illegal values!\n");
			return -1;
		}
	}

	rec_num_words = strtoll(argv[3], NULL, 10);

	ptr = header->order + (entry = rec_entry) * 3;
	memcpy(numbers, rec_numbers, sizeof(rec_numbers));

	last_count = last_length = -1;

	entry--;
	while (ptr < &header->order[sizeof(header->order) - 1]) {
		entry++;
		length = *ptr++; fixed = *ptr++; count = *ptr++;

		if (length >= CHARSET_LENGTH ||
			fixed > length ||
			count >= CHARSET_SIZE) inc_format_error(charset->file);

		if (entry != rec_entry){
			memset(numbers, 0, sizeof(numbers));
			num_cache = 0;
		}

		if (count >= real_count ||
			(int)length >= 32 ||
			(fixed && !count)) continue;

		if ((int)length + 1 < min_length ||
			(int)length >= max_length ||
			(int)count >= max_count) continue;

		if ((int)length != last_length) {
			inc_new_length(last_length = length,
				header, file, charset->file, char1, char2, chars);
			last_count = -1;
		}
		if ((int)count > last_count)
			inc_new_count(length, last_count = count, charset->file,
				allchars, char1, char2, chars);

		if (!length && !min_length) {
			min_length = 1;
		}

		if( inc_key_loop(length, fixed, count, char1, char2, chars, &num_cache) )
			break;
	}

	if( num_gen == 0 ){ /* DONE! */
		printf("DONE!\n");
		return 2;
	}

	printf("%d,%d,%d,",
		entry,  CHARSET_LENGTH, num_cache);

	for(pos=0;pos<CHARSET_LENGTH;pos++)
		printf("%d%c", numbers[pos], (pos == CHARSET_LENGTH-1) ? '\n' : ',');

	for (pos = 0; pos < (int)header->length - 2; pos++)
		free(chars[pos]);
	free(char2);
	free(header);

	fclose(file);

	return 0;
}
