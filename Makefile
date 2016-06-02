INCLUDE=src/crypto.java src/app.java
SRCDIR=-sourcepath ./src

all:
	javac $(SRCDIR) $(INCLUDE) src/encoder.java
	javac $(SRCDIR) $(INCLUDE) src/decoder.java
clean:
	rm -f src/*.class
