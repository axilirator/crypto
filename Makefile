all:
	gcc encode.c common.c -o encode
	gcc decode.c common.c -o decode

clean:
	rm encode decode
