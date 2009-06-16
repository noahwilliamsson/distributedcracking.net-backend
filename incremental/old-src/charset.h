/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

/*
 * Charset file generation.
 */

#ifndef _JOHN_CHARSET_H
#define _JOHN_CHARSET_H

#define PLAINTEXT_BUFFER_SIZE          0x80
#define CHARSET_VERSION			"CHR1"
#define CHARSET_MIN			' '
#define CHARSET_MAX			0x7E
#define CHARSET_SIZE			(CHARSET_MAX - CHARSET_MIN + 1)
#define CHARSET_LENGTH			8
#define CHARSET_SCALE			0x100

#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
#define CC_PACKED			__attribute__ ((packed))
#else
#define CC_PACKED			/* nothing */
#endif

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
/* CHARSET_VERSION */
	char version[4] CC_PACKED;

/* CHARSET_MIN, CHARSET_MAX */
	unsigned char min, max CC_PACKED;

/* CHARSET_LENGTH */
	unsigned char length CC_PACKED;

/* Number of different characters, up to (max - min + 1) */
	unsigned char count CC_PACKED;

/* File offsets for each length, 32-bit little endian */
	unsigned char offsets[CHARSET_LENGTH][4] CC_PACKED;

/*
 * Cracking order.
 *
 * This is a list of current {length, fixed position, character count}.
 * There're CHARSET_LENGTH different lengths, and fixed position is up
 * to the current length, which means we have exactly (CHARSET_LENGTH *
 * (CHARSET_LENGTH + 1) / 2) different {length, fixed position} pairs;
 * for each such pair we need to try all charsets from 1 character and
 * up to CHARSET_SIZE characters large.
 */
	unsigned char order
		[CHARSET_LENGTH * (CHARSET_LENGTH + 1) / 2 * CHARSET_SIZE * 3]
		CC_PACKED;
} CC_PACKED;

/*
 * Reads a charset file header.
 */
extern void charset_read_header(FILE *file, struct charset_header *header);

typedef struct{
	int min_length;
	int max_length;
	int max_count;
	char *file;
}t_ch;
#endif
