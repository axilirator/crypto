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
	fprintf(stderr, "Simple plaintext encoder demo\n"
		"Copyright (C) 2016 Yanitskiy Vadim <axilirator@gmail.com>\n\n");
}

static void print_help(const char *exec_patch)
{
	fprintf(stderr, "Usage: %s [options] -p <plaintext>\n\n"
		"Some help:\n"
		"  -p --plaintext <string> Plaintext string that should be encoded\n"
		"  -x --hex       <string> Plaintext in hexadecimal format\n"
		"  -k --key       <key>    Generate the gamma sequence using provided key\n"
		"  -g --gamma     <bytes>  Specify a gamma sequence (for example, 3FAA64)\n"
		"     --feedback           Enable cipher feedback mode\n", exec_patch);
}

static struct option long_options[] = {
	{"feedback", no_argument, &enable_feedback, 1},
	{"plaintext", required_argument, 0, 'p'},
	{"gamma", required_argument, 0, 'g'},
	{"hex", required_argument, 0, 'x'},
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
		c = getopt_long(argc, argv, "g:k:p:x:h", long_options, &option_index);

		// Detect the end of the options
		if (c == -1) break;

		switch (c) {
		case 'x':
			length = strlen(optarg) / 2;
			data.cipher_len = length;
			data.plain_len = length;
			input++;

			data.plaintext = (uint8_t *) malloc(length * sizeof(uint8_t));
			hexparse(optarg, data.plaintext, length);
			break;
		case 'p':
			input++;
			length = strlen(optarg);
			data.plain_len = length;
			data.cipher_len = length;
			char2byte(optarg, &data.plaintext, length);
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

	// Check if plaintext isn't specified
	if (input != 1) {
		rc = 1;
		fprintf(stderr, "[!] Please specify the plaintext that "
			"you are going to encode, see help.\n");
	}

	// Check if there is only one gamma source
	if (gamma_src != 1) {
		rc = 1;
		fprintf(stderr, "[!] You have to specify the key or gamma "
			"sequence to be able to encode the plaintext\n");
	}

	return rc;
}

int main(int argc, char **argv)
{
	int i, rc;

	print_header();
	rc = parse_argv(argc, argv);

	if (rc) {
		fprintf(stderr, "\n");
		print_help(argv[0]);
		return rc;
	}

	fprintf(stderr, "[i] %s\n", enable_feedback ?
		"Feedback mode enabled" : "Default ciphering mode");

	// Encode plaintext
	encode(&data, enable_feedback);

	fprintf(stderr, "[i] Using the following gamma sequence: ");
	for (i = 0; i < data.cipher_len; i++) {
		if (i > 20) {
			fprintf(stderr, "...");
			break;
		}

		fprintf(stderr, "%02X", data.gamma[i]);
	}
	fprintf(stderr, "\n\n");

	// Print result
	for (i = 0; i < data.cipher_len; i++) printf("%02X", data.ciphertext[i]);
	printf("\n");

	// Free the memory
	free_crypto_data(&data);

	return 0;
}
