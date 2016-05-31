#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common.h"

static void xor_with_gamma(uint8_t *a, uint8_t *b, uint8_t *c, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		c[i] = a[i] ^ b[i];
	}
}

static void xor_encode_feedback(uint8_t *a, uint8_t *b, uint8_t *c, size_t len)
{
	int i;

	// XOR the first byte
	c[0] = a[0] ^ b[0];

	for (i = 1; i < len; i++) {
		c[i] = a[i] ^ c[i - 1];
	}
}

static void xor_decode_feedback(uint8_t *a, uint8_t *b, uint8_t *c, size_t len)
{
	int i;

	for (i = len - 1; i > 0; i--) {
		c[i] = a[i] ^ a[i - 1];
	}

	// XOR the lastest byte
	c[i] = a[0] ^ b[0];
}

static void key2gamma(struct crypto_data_t *data, size_t gamma_len)
{
	int i, j;

	for (i = 0, j = 0; i < gamma_len; i++, j++) {
		// We should repeat a key sequence
		// if it's shorter than plaintext length
		if (j == data->key_len) j = 0;

		// Fill the gamma
		data->gamma[i] = data->key[j];
	}
}

void char2byte(const char *string, uint8_t **bytes, size_t len)
{
	int i;

	// Allocate an array
	*bytes = (uint8_t *) malloc(len * sizeof(uint8_t));

	// Fill allocated array
	for (i = 0; i < len; i++) {
		(*bytes)[i] = (uint8_t) string[i];
	}
}

void byte2char(uint8_t *bytes, char **string, size_t len)
{
	int i;

	// Allocate an array
	*string = (char *) malloc((len + 1) * sizeof(char));

	// Fill allocated array
	for (i = 0; i < len; i++) {
		(*string)[i] = (char) bytes[i];
	}

	// Terminate resulting string
	(*string)[i] = '\0';
}

int hexparse(const char *string, uint8_t *bytes, int max_len)
{
	int i, l, v;

	l = strlen(string);
	if ((l & 1) || ((l >> 1) > max_len))
		return -1;

	memset(bytes, 0x00, max_len);

	for (i = 0; i < l; i++) {
		char c = string[i];
		if (c >= '0' && c <= '9')
			v = c - '0';
		else if (c >= 'a' && c <= 'f')
			v = 10 + (c - 'a');
		else if (c >= 'A' && c <= 'F')
			v = 10 + (c - 'A');
		else
			return -1;

		bytes[i >> 1] |= v << (i & 1 ? 0 : 4);
	}

	return i >> 1;
}

int encode(struct crypto_data_t *data, int enable_feedback)
{
	size_t length = data->plain_len;

	// Allocate the memory for both gamma and ciphered string
	data->ciphertext = (uint8_t *) malloc(length * sizeof(uint8_t));
	data->gamma = (uint8_t *) malloc(length * sizeof(uint8_t));

	if (data->gamma == NULL || data->ciphertext == NULL) {
		fprintf(stderr, "Cannot allocate the memory!\n");
		return -1;
	}

	// Generate a gamma sequence using specified key
	key2gamma(data, length);

	// Encode the plaintext
	if (enable_feedback) {
		xor_encode_feedback(data->plaintext, data->gamma, data->ciphertext, length);
	} else {
		xor_with_gamma(data->plaintext, data->gamma, data->ciphertext, length);
	}

	return 0;
}

int decode(struct crypto_data_t *data, int enable_feedback)
{
	size_t length = data->cipher_len;

	// Allocate the memory for both gamma and plain string
	data->plaintext = (uint8_t *) malloc(length * sizeof(uint8_t));
	data->gamma = (uint8_t *) malloc(length * sizeof(uint8_t));

	if (data->gamma == NULL || data->plaintext == NULL) {
		fprintf(stderr, "Cannot allocate the memory!\n");
		return -1;
	}

	// Generate a gamma sequence using specified key
	key2gamma(data, length);

	// Decode the ciphertext
	if (enable_feedback) {
		xor_decode_feedback(data->ciphertext, data->gamma, data->plaintext, length);
	} else {
		xor_with_gamma(data->ciphertext, data->gamma, data->plaintext, length);
	}

	return 0;
}

void free_crypto_data(struct crypto_data_t *data)
{
	if (data->key != NULL) free(data->key);
	if (data->gamma != NULL) free(data->gamma);
	if (data->plaintext != NULL) free(data->plaintext);
	if (data->ciphertext != NULL) free(data->ciphertext);
}
