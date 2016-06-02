class Crypto
{
	protected byte[] ciphertext;
	protected byte[] plaintext;
	protected byte[] keystream;
	protected byte[] key;

	private byte[] xor(byte[] a, byte[] b)
	{
		int len = a.length;
		byte[] c = new byte[len];

		for (int i = 0; i < len; i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}

		return c;
	}

	private byte[] xor_encrypt_feedback(byte[] a)
	{
		int len = a.length;
		byte[] c = new byte[len];

		// XOR the first byte
		c[0] = (byte) (a[0] ^ this.keystream[0]);

		for (int i = 1; i < len; i++) {
			c[i] = (byte) (a[i] ^ c[i - 1]);
		}

		return c;
	}

	private byte[] xor_decrypt_feedback(byte[] a)
	{
		int len = a.length;
		byte[] c = new byte[len];

		for (int i = len - 1; i > 0; i--) {
			c[i] = (byte) (a[i] ^ a[i - 1]);
		}

		// XOR the lastest byte
		c[len - 1] = (byte) (a[0] ^ this.keystream[0]);

		return c;
	}

	protected void make_keystream()
	{
		int i, j, ks_len;
		int key_len = this.key.length;

		// (Re)allocate the memory
		ks_len = this.plaintext == null ? this.ciphertext.length : this.plaintext.length;
		this.keystream = new byte[ks_len];

		// Many-time padding
		for (i = 0, j = 0; i < ks_len; i++, j++) {
			// We should repeat a key sequence
			// if it's shorter than plaintext length
			if (j == key_len) j = 0;

			// Fill the keystream
			this.keystream[i] = this.key[j];
		}
	}

	public void encrypt(boolean feedback)
	{
		int len = this.plaintext.length;

		// Allocate the memory for both keystream and ciphertext
		this.keystream = new byte[len];
		this.ciphertext = new byte[len];

		// Prepare a keystream sequence
		this.make_keystream();

		// Encrypt the plaintext
		if (feedback) {
			this.ciphertext = this.xor_encrypt_feedback(this.plaintext);
		} else {
			this.ciphertext = this.xor(this.plaintext, this.keystream);
		}
	}

	public void decrypt(boolean feedback)
	{
		int len = this.ciphertext.length;

		// Allocate the memory for both keystream and plaintext
		this.keystream = new byte[len];
		this.plaintext = new byte[len];

		// Prepare a keystream sequence
		this.make_keystream();

		// Decrypt the ciphertext
		if (feedback) {
			this.plaintext = this.xor_encrypt_feedback(this.ciphertext);
		} else {
			this.plaintext = this.xor(this.ciphertext, this.keystream);
		}
	}
}
