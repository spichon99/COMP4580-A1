// COMP 4580 - Assignment 1
// Crypto_RSA
// Sebastien Pichon - 7840237
// Use Makefile to compile

#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a){
	char *number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
}


int main(){
	// Initial setup
	BN_CTX *ctx = BN_CTX_new();
	
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	
	BIGNUM *n = BN_new(); // p * q
	BIGNUM *totient = BN_new(); // (p-1)(q-1)
	BIGNUM *d = BN_new(); // d = modular inverse of e mod totient
	
	BIGNUM *m = BN_new(); // The message
	BIGNUM *c = BN_new(); // The ciphertext
	
	// Initialize p, q, e
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	
	// Calculate n
	BN_mul(n, p, q, ctx);
	
	// Calculate totient(n)
	BIGNUM *one = BN_new();
	BIGNUM *p_minus_one = BN_new();
	BIGNUM *q_minus_one = BN_new();
	BN_dec2bn(&one, "1");
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(totient, p_minus_one, q_minus_one, ctx);
	
	// Calculate d
	BN_mod_inverse(d, e, totient, ctx);
	
	// Print calculated values
	printf("=== Initial Setup ===\n");
	printBN("p = ", p);
	printBN("q = ", q);
	printBN("n = ", n);
	printBN("totient = ", totient);
	printBN("e = ", e);
	printBN("d = ", d);
	printf("\n");
	
	// Encrypting a message m
	printf("=== Encrypting a message ===\n");
	BN_hex2bn(&e,"010001");
	BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&m, "4120746f702073656372657421"); // "A top secret!"
	BN_mod_exp(c, m, e, n, ctx); // c = m^e mod n	
	
	printBN("The message m: ", m);
	printBN("The ciphertext c: ", c);
	printf("\n");
	
	// Decrypting a ciphertext c
	printf("=== Decrypting a ciphertext ===\n");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	BN_mod_exp(m, c, d, n, ctx); // m = c^d mod n
	
	printBN("The ciphertext c: ", c);
	printBN("The message m: ", m);
	
	return 0;
}
