#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#include "common.h"

struct crypto_data_t data;
int enable_feedback = 0;

static void print_header(void)
{
	fprintf(stderr, "Simple ciphertext decoder demo\n"
		"Copyright (C) 2016 Yanitskiy Vadim <axilirator@gmail.com>\n\n");
}

static void print_help(const char *exec_patch)
{
	fprintf(stderr, "Usage: %s [options] -c <ciphertext>\n\n"
		"Some help:\n"
		"  -C --ciphertext <string> Ciphertext string that should be decoded\n"
		"  -k --key        <key>    Generate the gamma sequence using provided key\n"
		"  -g --gamma      <bytes>  Specify a gamma sequence (for example, 3FAA64)\n"
		"     --feedback            Enable cipher feedback mode\n", exec_patch);
}

static struct option long_options[] = {
	{"feedback", no_argument, &enable_feedback, 1},
	{"ciphertext", required_argument, 0, 'C'},
	{"gamma", required_argument, 0, 'g'},
	{"key", required_argument, 0, 'k'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static int parse_argv(int argc, char **argv)
{
	int option_index, c;
	int length, rc = 0;
	int gamma_src = 0;
	int input = 0;

	while (1) {
		// getopt_long() stores the option index here
		option_index = 0;

		// Try to parse a new option
		c = getopt_long(argc, argv, "g:k:C:h", long_options, &option_index);

		// Detect the end of the options
		if (c == -1) break;

		switch (c) {
		case 'C':
			length = strlen(optarg) / 2;
			data.cipher_len = length;
			data.plain_len = length;
			input++;

			data.ciphertext = (uint8_t *) malloc(length * sizeof(uint8_t));
			hexparse(optarg, data.ciphertext, length);
			break;
		case 'g':
			data.key_len = strlen(optarg) / 2;
			gamma_src++;

			if (data.key_len > 0) {
				data.key = (uint8_t *) malloc(data.key_len * sizeof(uint8_t));
				hexparse(optarg, data.key, data.key_len);
			} else {
				fprintf(stderr, "Cannot parse specified gamma bytes, see help.\n");
				rc = 1;
			}
			break;
		case 'k':
			gamma_src++;
			data.key_len = strlen(optarg);
			char2byte(optarg, &data.key, data.key_len);
			break;
		case 'h':
			print_help(argv[0]);
			exit(0);
		case '?':
			rc = 1;
			break;
		}
	}

	// Check if ciphertext isn't specified
	if (!input) {
		rc = 1;
		fprintf(stderr, "[!] Please specify the ciphertext that "
			"you are going to decode, see help.\n");
	}

	// Check if there is only one gamma source
	if (gamma_src != 1) {
		rc = 1;
		fprintf(stderr, "[!] You have to specify the key or gamma "
			"sequence to be able to decode the ciphertext\n");
	}

	return rc;
}

int main(int argc, char **argv)
{
	int i, rc;
	char *result;

	print_header();
	rc = parse_argv(argc, argv);

	if (rc) {
		fprintf(stderr, "\n");
		print_help(argv[0]);
		return rc;
	}

	fprintf(stderr, "[i] %s\n", enable_feedback ?
		"Feedback mode enabled" : "Default ciphering mode");

	// Decode ciphertext
	decode(&data, enable_feedback);

	fprintf(stderr, "[i] Using the following gamma sequence: ");
	for (i = 0; i < data.plain_len; i++) {
		if (i > 20) {
			fprintf(stderr, "...");
			break;
		}

		fprintf(stderr, "%02X", data.gamma[i]);
	}
	fprintf(stderr, "\n\n");

	// Print result
	byte2char(data.plaintext, &result, data.plain_len);
	printf("%s\n", result);

	// Free the memory
	free_crypto_data(&data);

	return 0;
}
