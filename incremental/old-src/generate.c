/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003 by Solar Designer
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "charset.h"

#define TJOHN_CHARSET_PATH "/opt/distributedcracking.net/backend/incremental/"
//#define TJOHN_CHARSET_PATH ""

t_ch charsetinfo[] = { 
	// min length, max length, character count, path
	{ 0, 8, 95, TJOHN_CHARSET_PATH "all.chr" },
	{ 1, 8, 26, TJOHN_CHARSET_PATH "alpha.chr" },
	{ 1, 8, 10, TJOHN_CHARSET_PATH "digits.chr" },
	{ 0, 7, 69, TJOHN_CHARSET_PATH "lanman.chr" },
	{ 0, 8, 38, TJOHN_CHARSET_PATH "vms.chr" } 
};

#define ARCH_INDEX(x)	((unsigned int)(unsigned char)(x))

typedef char (*char2_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1];
typedef char (*chars_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1][CHARSET_SIZE + 1];

static int rec_compat;
static int rec_entry;
static int rec_numbers[CHARSET_LENGTH];
unsigned long long rec_num_words;
static unsigned long long num_gen = 0;

static int entry;
static int numbers[CHARSET_LENGTH];

static void inc_format_error(char *charset)
{
	fprintf(stderr, "Incorrect charset file format: %s\n", charset);
	exit(-1);
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
		(long)header->offsets[length][0] +
		((long)header->offsets[length][1] << 8) +
		((long)header->offsets[length][2] << 16) +
		((long)header->offsets[length][3] << 24);
	if (fseek(file, offset, SEEK_SET)) { fprintf(stderr,"fseek"); exit(-1); }

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
			if ((unsigned int)value > length)
				inc_format_error(charset);
			pos = value;
		} else
		if (value == CHARSET_LINE) {
			if (pos < 0)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF) break;
			if ((unsigned int)(i = value) > CHARSET_SIZE)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF) break;
			if ((unsigned int)(j = value) > CHARSET_SIZE)
				inc_format_error(charset);
		} else
			inc_format_error(charset);

		value = getc(file);
	} while (value != EOF);

	if (value == EOF) {
		if (ferror(file)){
			fprintf(stderr,"getc\n"); exit(-1);
		}else
			inc_format_error(charset);
	}
}

static void expand(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;
	char present[CHARSET_SIZE];

	memset(present, 0, sizeof(present));
	while (*dptr) {
		if (--count <= 1) return;
		present[ARCH_INDEX(*dptr++) - CHARSET_MIN] = 1;
	}

	while (*sptr)
	if (!present[ARCH_INDEX(*sptr) - CHARSET_MIN]) {
		*dptr++ = *sptr++;
		if (--count <= 1) break;
	} else
		sptr++;
	*dptr = 0;
}

static void inc_new_count(unsigned int length, int count,
	char *allchars, char *char1, char2_table char2, chars_table *chars)
{
	int pos, i, j;
	int size;

	size = count + 2;

	expand(char1, allchars, size);
	if (length)
		expand((*char2)[CHARSET_SIZE], allchars, size);
	for (pos = 0; pos <= (int)length - 2; pos++)
		expand((*chars[pos])[CHARSET_SIZE][CHARSET_SIZE],
			allchars, size);

	for (i = 0; i < CHARSET_SIZE; i++) {
		if (length)
			expand((*char2)[i], (*char2)[CHARSET_SIZE], size);

		for (j = 0; j < CHARSET_SIZE; j++)
		for (pos = 0; pos <= (int)length - 2; pos++) {
			expand((*chars[pos])[i][j], (*chars[pos])
				[CHARSET_SIZE][j], size);
			expand((*chars[pos])[i][j], (*chars[pos])
				[CHARSET_SIZE][CHARSET_SIZE], size);
		}
	}
}

static inline int inc_key_loop(int length, int fixed, int count,
	char *char1, char2_table char2, chars_table *chars, int *num_cache)
{
	char *chars_cache;
	int numbers_cache;
	int first_run = 1;
	int pos;

	numbers[fixed] = count;

	chars_cache = NULL;

update_all:
update_ending:
	if( first_run && num_cache ){
		numbers_cache = *num_cache;	
		first_run = 0;
	}else
		numbers_cache = numbers[length];

update_last:

	if( (num_gen ++) >= rec_num_words ){
		if( num_cache )
			*num_cache = numbers_cache;
		return 2;
	}

	if( rec_compat) goto compat;

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

int main(int argc, char *argv[])
{
	t_ch *charset;
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

	if( ! strcmp(argv[1], "all") ){
		charset = &charsetinfo[0];
	}else if( ! strcmp(argv[1], "alpha") ){
		charset = &charsetinfo[1];
	}else if( ! strcmp(argv[1], "digits") ){
		charset = &charsetinfo[2];
	}else if( ! strcmp(argv[1], "lanman") ){
		charset = &charsetinfo[3];
	}else if( ! strcmp(argv[1], "vms") ){
		charset = &charsetinfo[4];
	}else{
		fprintf(stderr,"Illegal value for charset!\n");
		return -1;
	}

	min_length = charset->min_length;
	max_length = charset->max_length;
	max_count = charset->max_count;

	if (!(file = fopen(charset->file, "rb"))){
		fprintf(stderr,"Cannot open file '%s': %s\n", charset->file, strerror(errno));
		exit(-2);
	}

	header = (struct charset_header *)malloc(sizeof(*header));

	charset_read_header(file, header);
	if (ferror(file)) { fprintf(stderr,"fread: %s\n", strerror(errno)); exit(-2); }

	if (feof(file) ||
	    memcmp(header->version, CHARSET_VERSION, sizeof(header->version)) ||
	    header->min != CHARSET_MIN || header->max != CHARSET_MAX ||
	    header->length != CHARSET_LENGTH ||
	    header->count > CHARSET_SIZE || !header->count)
		inc_format_error(charset->file);

	fread(allchars, header->count, 1, file);
	if (ferror(file)) { fprintf(stderr,"fread: %s\n", strerror(errno)); exit(-1); }
	if (feof(file)) inc_format_error(charset->file);

	allchars[header->count] = 0;
/*
	if (extra)
		expand(allchars, extra, sizeof(allchars));
*/
	real_count = strlen(allchars);

	if (max_count < 0) max_count = CHARSET_SIZE;

	if ((unsigned int)max_count > real_count) {
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
		
	if((ptr = strchr(argv[2], ',')) == NULL 
		|| (ptr = strchr(ptr, ',')) == NULL
		|| (ptr = strchr(ptr, ',')) == NULL) {

		fprintf(stderr,"Illegal packet-info field!\n");
		fclose(file); free(header);
		return -1;
	}
	ptr++;
	for(pos=0;pos<length;pos++){
		rec_numbers[pos] = strtol(ptr, NULL, 10);
		ptr = strstr(ptr, ","); ptr++;

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
			inc_new_count(length, last_count = count,
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
