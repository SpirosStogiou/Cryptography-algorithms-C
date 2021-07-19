#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <assert.h>

gmp_randstate_t stat;


typedef struct {
    mpz_t p;
    mpz_t a;
    mpz_t a_d;
} public_key;

typedef struct {
    mpz_t d;
} private_key;


void createKeys(private_key* privateKey, public_key* publicKey) {

    long sd = 0;
    int primeTestFor_p,primeTestFor_a;
    mpz_t p,a,d,a_d;
    mpz_t seed;



    gmp_randinit_default(stat);
    gmp_randinit(stat, GMP_RAND_ALG_LC, 200 );
    mpz_init(p);
    mpz_init(a);
    mpz_init(d);
    mpz_init(a_d);
    mpz_init(seed);


    sd=rand();

    mpz_set_ui(seed, sd);

    gmp_randseed(stat, seed);

    mpz_urandomb(p, stat, 200);
    mpz_urandomb(a, stat, 200);

    printf("Generate one 200-bit random number p ,the ganerator a (Zp*) ,the random number d and a^d:\n");


    primeTestFor_p= mpz_probab_prime_p(p, 10);

    if(primeTestFor_p == 0) {
        mpz_nextprime(p, p);
    }
    primeTestFor_a= mpz_probab_prime_p(a, 10);
    if(primeTestFor_a==0) {
        mpz_nextprime(a, a);
    }

    while( mpz_cmp(p,a)<0) {
        mpz_urandomb(a,stat,200);
    }

    printf("\np = %s\n", mpz_get_str(NULL, 0, p));
    printf("a = %s\n", mpz_get_str(NULL, 0, a));


    mpz_urandomb(d,stat,200);

    while( mpz_cmp(p,d)<0 ) {
        mpz_urandomb(d,stat,200);

    }

    printf("d = %s\n", mpz_get_str(NULL, 0, d));

    mpz_powm(a_d,a,d,p);

    printf("a^d = %s\n", mpz_get_str(NULL, 0, a_d));


    mpz_set(privateKey->d,d);

    mpz_set(publicKey->p,p);
    mpz_set(publicKey->a,a);
    mpz_set(publicKey->a_d,a_d);


    printf("\nPrint the values of Public and Private keys : \n");
    printf("Public key : (p: %s, a: %s a^d: %s)\n", mpz_get_str(NULL, 0, p), mpz_get_str(NULL, 0, a), mpz_get_str(NULL, 0, a_d));
    printf("Private key : (d: %s )\n", mpz_get_str(NULL, 0, d));


    mpz_clear(p);
    mpz_clear(a);
    mpz_clear(d);
    mpz_clear(a_d);
    mpz_clear(seed);


}

void encrypt(mpz_t *ciphertext,mpz_t c,char* msg,public_key publicKey) {

    int length = 0;
    mpz_t k;

    mpz_init(k);
    mpz_init(c);

    while(msg[length]!='\0') {
        length++;
    }



    mpz_urandomb(k,stat,200);


    while( mpz_cmp(publicKey.p,k)<0 ) {
        mpz_urandomb(k,stat,200);
    }

    printf("\nk = %s \n", mpz_get_str(NULL, 0, k));

    mpz_powm(c,publicKey.a,k,publicKey.p);

    gmp_printf("\nc = %s \n", mpz_get_str(NULL, 0, c));



    int i;
    ciphertext[length];
    for (i = 0; i < length; i++) {
        mpz_init(ciphertext[i]);
    }



    mpz_t temp_powm;
    mpz_init(temp_powm);


    mpz_powm(temp_powm,publicKey.a_d,k,publicKey.p);

    gmp_printf("\n((a^d)^k)mod p = %Zd \n\n",temp_powm);

    printf("Original message : ");
    for (i = 0; i < length; i++) {
        printf("%c", msg[i]);
    }
    printf("\n");

    printf("Encrypted message : \n");

    for(i=0; i<length; i++) {

        mpz_mul_si(ciphertext[i],temp_powm,msg[i]);

        gmp_printf("%Zd",ciphertext[i]);

    }

    mpz_clear(temp_powm);
    mpz_clear(c);
    mpz_clear(k);

}

void decrypt(mpz_t c,mpz_t* ciphertext,int length,public_key publicKey,private_key privateKey) {
    int original,i;

    mpz_t tmp_powm;
    mpz_init(tmp_powm);
    mpz_t tmp_div;
    mpz_init(tmp_div);

    printf("\n\nDecrypted message: ");

    for(i=0; i<length; i++) {

        mpz_powm(tmp_powm,c,privateKey.d,publicKey.p);
        mpz_cdiv_q(tmp_div,ciphertext[i],tmp_powm);
        original = mpz_get_ui(tmp_div);
        gmp_printf("%c",original);

    }

    printf("\n");


    mpz_clear(tmp_powm);
    mpz_clear(tmp_div);
    mpz_clear(c);

    for (i = 0; i < length; i++) {
        mpz_clear(ciphertext[i]);
    }

}

void display_encrypt_decrypt_message(char* msg,public_key publicKey,private_key privateKey) {
    int length=0, i;

    while(msg[length]!='\0') {
        length++;
    }
    mpz_t ciphertext[length];
    mpz_t c;
    mpz_init(c);
    mpz_init(ciphertext[length]);

    encrypt(ciphertext,c,msg,publicKey);
    decrypt(c,ciphertext,length,publicKey,privateKey);

    //CLEARS
    mpz_clear(c);
    for (i = 0; i < length; i++) {
        mpz_clear(ciphertext[i]);
    }

}


int main(void) {
    private_key privateKey;
    public_key publicKey;

    mpz_init(publicKey.a);
    mpz_init(publicKey.p);
    mpz_init(publicKey.a_d);

    mpz_init(privateKey.d);


    createKeys(&privateKey,&publicKey);
    display_encrypt_decrypt_message("This is a message for testing",publicKey,privateKey);


    return 0;
}
