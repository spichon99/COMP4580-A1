all: rsa.c
	gcc rsa.c -lcrypto -o rsa

clean:
	rm rsa
	
