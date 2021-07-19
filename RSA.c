#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <assert.h>


#define MAXLEN 256

gmp_randstate_t stat;


typedef struct {
    mpz_t n;
    mpz_t e;
} public_key;

typedef struct {
    mpz_t n;
    mpz_t d;
} private_key;


void createKeysRSA(private_key* privateKey, public_key* publicKey) {


    long sd = 0;
    int primeTestFor_p,primeTestFor_q;
    mpz_t p, q, n,e;
    mpz_t seed;


    gmp_randinit_default(stat);
    gmp_randinit(stat, GMP_RAND_ALG_LC, 521);
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(e);
    mpz_init(seed);


    sd=rand();

    mpz_set_ui(seed, sd);

    gmp_randseed(stat, seed);

    mpz_urandomb(p, stat, 521);
    mpz_urandomb(q, stat, 521);

    printf("Generate two 521-bit random numbers p and q:\n");

    primeTestFor_p= mpz_probab_prime_p(p, 10);

    if(primeTestFor_p == 0) {
        mpz_nextprime(p, p);
        printf("p = ");
        mpz_out_str(stdout, 10, p);
        printf("\n");
    } else {
        printf("p = ");
        mpz_out_str(stdout, 10, p);
        printf("\n");
    }

    primeTestFor_q= mpz_probab_prime_p(q, 10);
    if(primeTestFor_q==0) {
        mpz_nextprime(q, q);
        printf("q = ");
        mpz_out_str(stdout, 10, q);
        printf("\n");
    } else {
        printf("q = ");
        mpz_out_str(stdout, 10, q);
        printf("\n");

    }

    mpz_mul(n, p, q);
    mpz_t tmp_p, tmp_q,f, gcd, mul, mod,d;
    mpz_inits(tmp_p, tmp_q,f, gcd, mul, mod,d, NULL);
    mpz_sub_ui(tmp_p, p, 1);
    mpz_sub_ui(tmp_q, q, 1);

    mpz_lcm(f, tmp_p, tmp_q);
    printf("Create n and f: \n");
    printf("n = %s\n", mpz_get_str(NULL, 0, n));
    printf("f(n) = %s\n", mpz_get_str(NULL, 0, f));



    mpz_urandomb(e, stat, 256);


    mpz_gcd(gcd, e, f);
    while(mpz_cmp_ui(gcd, 1)) {
        mpz_nextprime(e,e);
        mpz_gcd(gcd, e, f);
    }


    assert(mpz_cmp_ui(e, 1) > 0);


    assert(mpz_cmp(f, e) > 0);


    mpz_gcd(gcd, e, f);
    assert(mpz_cmp_ui(gcd, 1) == 0);
    printf("Create e and d: \n");
    printf("e = %s\n", mpz_get_str(NULL, 0, e));



    mpz_invert(d, e, f);//


    mpz_mul(mul, e, d);
    mpz_mod(mod, mul, f);
    assert(mpz_cmp_ui(mod, 1) == 0);
    printf("d = %s\n", mpz_get_str(NULL, 0, d));



    mpz_set(privateKey->d,d);
    mpz_set(privateKey->n,n);
    mpz_set(publicKey->e,e);
    mpz_set(publicKey->n,n);


    printf("Print the values of Public and Private keys : \n");
    printf("Public key : (e: %s, n: %s)\n", mpz_get_str(NULL, 0, e), mpz_get_str(NULL, 0, n));
    printf("Private key : (d: %s, n: %s)\n", mpz_get_str(NULL, 0, d), mpz_get_str(NULL, 0, n));

    //CLEAR
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(d);
    mpz_clear(seed);
    mpz_clears(gcd, tmp_p, tmp_q, mul, mod, f, NULL);

}

void convert_msg_to_integer(mpz_t integer_msg, char *msg) {

    int len, j;

    unsigned char my_char;

    len = strlen(msg);

    if(msg[len - 1] == '\n'){
         msg[len - 1] = '\0';
    }

    mpz_set_ui(integer_msg, 0UL);

    for(j = len - 1; j >= 0; j--) {


        my_char = msg[j];
        mpz_mul_ui(integer_msg, integer_msg, (unsigned long)MAXLEN);
        mpz_add_ui(integer_msg, integer_msg, (unsigned long)my_char);

    }


}

void convert_integer_to_msg(char *first_msg, mpz_t converted_msg) {

    long int str_len, i;
    mpz_t max_int, int_character, tmp_converted_msg;

    mpz_init(max_int);
    mpz_init(int_character);
    mpz_init(tmp_converted_msg);

    mpz_set(tmp_converted_msg, converted_msg);
    mpz_set_ui(max_int, 1UL);

    for(i = 0; i < MAXLEN; i++) {
        if(mpz_cmp(tmp_converted_msg, max_int) <= 0) {
            str_len = i;
            break;
        }
       mpz_mul_ui(max_int, max_int, (unsigned long)MAXLEN);
    }



    for(i = 0; i < str_len; i++) {

        mpz_mod_ui(int_character, tmp_converted_msg, (unsigned long)MAXLEN);
        mpz_sub(tmp_converted_msg, tmp_converted_msg, int_character);
        mpz_tdiv_q_ui(tmp_converted_msg, tmp_converted_msg, (unsigned long)MAXLEN);


        first_msg[i] = mpz_get_ui(int_character);

    }

    first_msg[str_len] = '\0';

    mpz_clear(max_int);

    mpz_clear(int_character);

    mpz_clear(tmp_converted_msg);

}

void encrypt(mpz_t encrypted, mpz_t message, public_key publicKey) {

    mpz_powm(encrypted, message, publicKey.e, publicKey.n);
    return;
}

void decrypt(mpz_t first_msg, mpz_t encrypted, private_key privateKey) {
    //first_msg=encrypted^d mod n
    mpz_powm(first_msg, encrypted, privateKey.d, privateKey.n);
    return;
}

void display_encrypt_decrypt_message(char* msg,public_key publicKey,private_key privateKey) {
    char firstmsg[250];
    mpz_t int_message;
    mpz_t encrypted, decrypted;
    mpz_inits(int_message,encrypted, decrypted, NULL);

    convert_msg_to_integer(int_message,msg);


    encrypt(encrypted, int_message, publicKey);
    decrypt(decrypted, encrypted, privateKey);


    convert_integer_to_msg(firstmsg,decrypted);


    assert(mpz_cmp(int_message, decrypted) == 0);

    printf("----------------------------------------------------\n");
    printf("The first message: %s\n", msg);
    printf("\nThe integer number from message: %s\n", mpz_get_str(NULL, 0, int_message));
    printf("\nThe encrypted message: %s\n", mpz_get_str(NULL, 0, encrypted));
    printf("\nThe integer number decrypted from message: %s\n", mpz_get_str(NULL, 0, decrypted));
    printf("\nThe decrypted message: %s\n", firstmsg);
    printf("\n");
    //Clear
    mpz_clears(encrypted,decrypted,int_message, NULL);
}


int main() {

    private_key privateKey;
    public_key publicKey;

    mpz_init(publicKey.n);
    mpz_init(publicKey.e);

    mpz_init(privateKey.n);
    mpz_init(privateKey.d);


    createKeysRSA(&privateKey,&publicKey);

    display_encrypt_decrypt_message("This is a message for testing",publicKey,privateKey);
    printf("----------------------------------------------------\n");



    return 0;
}
