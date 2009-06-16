/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "charset.h"

void charset_read_header(FILE *file, struct charset_header *header)
{
#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
	fread(header, sizeof(*header), 1, file);
#else
	fread(header->version, sizeof(header->version), 1, file);
	header->min = getc(file);
	header->max = getc(file);
	header->length = getc(file);
	header->count = getc(file);
	fread(header->offsets, sizeof(header->offsets), 1, file);
	fread(header->order, sizeof(header->order), 1, file);
#endif
}
