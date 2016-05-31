struct crypto_data_t {
	uint8_t *ciphertext;
	uint8_t *plaintext;
	uint8_t *gamma;
	uint8_t *key;

	size_t cipher_len;
	size_t plain_len;
	size_t key_len;
};

void free_crypto_data(struct crypto_data_t *data);
int encode(struct crypto_data_t *data, int enable_feedback);
int decode(struct crypto_data_t *data, int enable_feedback);

void byte2char(uint8_t *bytes, char **string, size_t len);
void char2byte(const char *string, uint8_t **bytes, size_t len);
int hexparse(const char *string, uint8_t *bytes, int max_len);
