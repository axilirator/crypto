import gnu.getopt.LongOpt;
import gnu.getopt.Getopt;

class Encoder extends App {
	public void print_help()
	{
		System.out.print(
			"Usage: java encoder [options] -p <plaintext>\n\n" +
			"Some help:\n" +
			"  -p --plaintext <string> Plaintext string that should be encoded\n" +
			"  -P --hex       <string> Plaintext in hexadecimal format\n" +
			"  -k --key       <key>    Generate a keystream sequence using provided key\n" +
			"  -K --keystream <bytes>  Specify a keystream sequence (for example, 3FAA64)\n" +
			"     --feedback           Enable cipher feedback mode\n"
		);
	}

	public void parse_argv(String[] argv)
	{
		StringBuffer sb = new StringBuffer();
		int plain_src = 0, ks_src = 0;
		boolean error = false;
		int c, length;
		String optarg;

		LongOpt[] longopts = {
			new LongOpt("plaintext", LongOpt.REQUIRED_ARGUMENT, sb, 'p'),
			new LongOpt("keystream", LongOpt.REQUIRED_ARGUMENT, sb, 'K'),
			new LongOpt("hex", LongOpt.REQUIRED_ARGUMENT, sb, 'P'),
			new LongOpt("key", LongOpt.REQUIRED_ARGUMENT, sb, 'k'),
			new LongOpt("feedback", LongOpt.NO_ARGUMENT, null, 'f')
		};

		Getopt g = new Getopt("Encoder", argv, "K:k:P:p:h", longopts);
		while ((c = g.getopt()) != -1) {
			optarg = g.getOptarg();

			if (c == 0) {
				// Handle long options
				c = (char)(new Integer(sb.toString())).intValue();
			}

			switch (c) {
			case 'P':
				this.plaintext = hexparse(optarg);
				plain_src++;

				// Check if incoming string was parsed correctly
				if (this.plaintext == null) {
					System.out.println("Please, check incoming hexadecimal string!");
					error = true;
				}

				break;
			case 'p':
				this.plaintext = optarg.getBytes();
				plain_src++;
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

		// Check if plaintext isn't specified
		if (plain_src != 1) {
			error = true;
			System.out.println("[!] Please specify the plaintext that " +
				"you are going to cypher, see help.");
		}

		// Check if there is only one keystream source
		if (ks_src != 1) {
			error = true;
			System.out.println("[!] You have to specify the key or keystream " +
				"sequence to be able to cypher the plaintext.");
		}

		if (error) {
			System.out.println();
			this.print_help();
			System.exit(1);
		}
	}

	public static void main(String[] argv)
	{
		Encoder ec = new Encoder();

		ec.print_header();
		ec.parse_argv(argv);

		// Print debug info
		System.out.printf("[i] %s\n", ec.feedback ?
			"Feedback mode enabled" : "Default ciphering mode");

		ec.print_keystream();
		System.out.println();

		// Encrypt specified plaintext
		ec.encrypt(ec.feedback);

		// Print encrypted sequence
		ec.print_ciphertext();
	}
}
