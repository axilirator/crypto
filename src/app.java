class App extends Crypto
{
	public boolean feedback;
	
	public void print_header()
	{
		System.out.print(
			"Simple XOR cipher implementation\n" +
			"Copyright (C) 2016 Yanitskiy Vadim <axilirator@gmail.com>\n\n"
		);
	}

	public void print_keystream()
	{
		// Prepare a keystream sequence
		this.make_keystream();

		System.out.print("[i] Using the following gamma sequence: ");
		for (int i = 0; i < this.keystream.length; i++) {
			if (i > 20) {
				System.out.print("...");
				break;
			}

			System.out.printf("%02X", this.keystream[i]);
		}

		// Terminate the string
		System.out.println();
	}

	public void print_ciphertext()
	{
		if (this.ciphertext == null) return;

		for (int i = 0; i < this.ciphertext.length; i++) {
			System.out.printf("%02X", this.ciphertext[i]);
		}

		// Terminate the string
		System.out.println();
	}

	public void print_plaintext()
	{
		if (this.plaintext == null) return;

		for (int i = 0; i < this.plaintext.length; i++) {
			System.out.printf("%c", this.plaintext[i]);
		}

		// Terminate the string
		System.out.println();
	}

	protected byte[] hexparse(String string)
	{
		int i, len, v;
		byte[] result;
		char c;

		// Get string length and check if it's even
		len = string.length();
		if (len % 2 != 0) {
			return null;
		}

		// Allocate a byte-array
		result = new byte[len / 2];

		for (i = 0; i < len; i++) {
			c = string.charAt(i);

			if (c >= '0' && c <= '9') {
				v = c - '0';
			} else if (c >= 'a' && c <= 'f') {
				v = 10 + (c - 'a');
			} else if (c >= 'A' && c <= 'F') {
				v = 10 + (c - 'A');
			} else {
				return null;
			}

			result[i >> 1] |= v << ((i & 1) != 0 ? 0 : 4);
		}

		return result;
	}
}
