import gnu.getopt.LongOpt;
import gnu.getopt.Getopt;

class Decoder extends App {
	public void print_help()
	{
		System.out.print(
			"Usage: java decoder [options] -C <ciphertext>\n\n" +
			"Some help:\n" +
			"  -C --ciphertext <string> Ciphertext string that should be decyphered\n" +
			"  -k --key       <key>     Generate a keystream sequence using provided key\n" +
			"  -K --keystream <bytes>   Specify a keystream sequence (for example, 3FAA64)\n" +
			"     --feedback            Enable cipher feedback mode\n"
		);
	}

	public void parse_argv(String[] argv)
	{
		StringBuffer sb = new StringBuffer();
		int cipher_src = 0, ks_src = 0;
		boolean error = false;
		int c, length;
		String optarg;

		LongOpt[] longopts = {
			new LongOpt("ciphertext", LongOpt.REQUIRED_ARGUMENT, sb, 'C'),
			new LongOpt("keystream", LongOpt.REQUIRED_ARGUMENT, sb, 'K'),
			new LongOpt("key", LongOpt.REQUIRED_ARGUMENT, sb, 'k'),
			new LongOpt("feedback", LongOpt.NO_ARGUMENT, null, 'f')
		};

		Getopt g = new Getopt("Encoder", argv, "C:K:k:h", longopts);
		while ((c = g.getopt()) != -1) {
			optarg = g.getOptarg();

			if (c == 0) {
				// Handle long options
				c = (char)(new Integer(sb.toString())).intValue();
			}

			switch (c) {
			case 'C':
				this.ciphertext = hexparse(optarg);
				cipher_src++;

				// Check if incoming string was parsed correctly
				if (this.ciphertext == null) {
					System.out.println("Please, check incoming hexadecimal string!");
					error = true;
				}

				break;
			case 'k':
				this.key = optarg.getBytes();
				ks_src++;
				break;
			case 'K':
				this.key = hexparse(optarg);
				ks_src++;

				// Check if incoming string was parsed correctly
				if (this.key == null) {
					System.out.println("Please, check incoming hexadecimal string!");
					error = true;
				}

				break;
			case 'f':
				this.feedback = true;
				break;
			case 'h':
				this.print_help();
				System.exit(0);
			default:
				System.out.println("Hey, whats wrong?");
				error = true;
			}
		}

		// Check if ciphertext isn't specified
		if (cipher_src != 1) {
			error = true;
			System.out.println("[!] Please specify the ciphertext that " +
				"you are going to decypher, see help.");
		}

		// Check if there is only one keystream source
		if (ks_src != 1) {
			error = true;
			System.out.println("[!] You have to specify the key or keystream " +
				"sequence to be able to decypher the ciphertext.");
		}

		if (error) {
			System.out.println();
			this.print_help();
			System.exit(1);
		}
	}

	public static void main(String[] argv)
	{
		Decoder dc = new Decoder();

		dc.print_header();
		dc.parse_argv(argv);

		// Print debug info
		System.out.printf("[i] %s\n", dc.feedback ?
			"Feedback mode enabled" : "Default ciphering mode");

		dc.print_keystream();
		System.out.println();

		// Decrypt specified ciphertext
		dc.decrypt(dc.feedback);

		// Print decrypted sequence
		dc.print_plaintext();
	}
}
