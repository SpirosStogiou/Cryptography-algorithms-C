#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <assert.h>

#define MAXLEN 256


gmp_randstate_t stat;
gmp_randstate_t rand_state;


typedef struct {
    mpz_t n;
} public_key;

typedef struct {
    mpz_t p;
    mpz_t q;
} private_key;



void createKeysRabin(private_key* privateKey, public_key* publicKey) {
    long sd = 0;
    int primetest;
    mpz_t sd1,p,q,p1,q1,n,pmod,qmod,seed;

    gmp_randinit_default(rand_state);
    gmp_randinit(stat, GMP_RAND_ALG_LC, 120);

    mpz_init(p);
    mpz_init(q);
    mpz_init(p1);
    mpz_init(q1);
    mpz_init(n);
    mpz_init(pmod);
    mpz_init(qmod);
    mpz_init(seed);


    printf("Generate two 200-bit random numbers p and q which is equivalent with 3 mod 4:\n");

    srand( (unsigned) getpid());
    sd=rand();
    mpz_set_ui(seed, sd);
    gmp_randseed(stat, seed);

goto_mpz_urandomb_p:
    mpz_urandomb(p1, stat, 200);


    primetest = mpz_probab_prime_p(p1, 5);

    if (primetest != 0){

        mpz_set(p, p1);

        mpz_sub_ui(pmod,p,3);
        mpz_mod_ui(pmod, pmod, 4);

        if (mpz_cmp_ui(pmod,0)!=0){
            goto goto_mpz_urandomb_p;
        }else {
            printf("p= %s \n",mpz_get_str(NULL, 0, p));
        }

    }else{

        mpz_nextprime(p, p1);
        mpz_sub_ui(pmod,p,3);
        mpz_mod_ui(pmod, pmod, 4);

        if (mpz_cmp_ui(pmod,0)!=0){
            goto goto_mpz_urandomb_p;
        }else{
          printf("p= %s \n",mpz_get_str(NULL, 0, p));
        }

    }

//Δημιουργια q

    srand( (unsigned) getpid());
    sd=rand();
    mpz_set_ui(seed, sd);
    gmp_randseed(stat, seed);


goto_mpz_urandomb_q:
    mpz_urandomb(q1, stat, 200);


    primetest = mpz_probab_prime_p(q1, 5);

    if (primetest != 0){

        mpz_set(q, q1);

        mpz_sub_ui(qmod,q,3);
        mpz_mod_ui(qmod, qmod, 4);

        if (mpz_cmp_ui(qmod,0)!=0){
            goto goto_mpz_urandomb_q;

        }else{
            printf("q= %s \n",mpz_get_str(NULL, 0, q));
        }

    }else{

        mpz_sub_ui(qmod,q,3);
        mpz_mod_ui(qmod, qmod, 4);

        if (mpz_cmp_ui(qmod,0)!=0){
            goto goto_mpz_urandomb_q;

        }else{
           printf("q= %s \n",mpz_get_str(NULL, 0, q));
        }

    }


    printf("Create n = p * q \n");
    mpz_mul(n, p, q);

    printf("n= %s \n",mpz_get_str(NULL, 0, n));


    mpz_set(publicKey->n,n);
    mpz_set(privateKey->p,p);
    mpz_set(privateKey->q,q);

    printf("Print the values of Public and Private keys : \n");
    printf("Public key : (n: %s)\n", mpz_get_str(NULL, 0, n));
    printf("Private key : (p: %s, q: %s)\n", mpz_get_str(NULL, 0, p), mpz_get_str(NULL, 0, q));

    //CLEAR
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(pmod);
    mpz_clear(qmod);
    mpz_clear(seed);

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

        //integer_msg = msg[str_len - 1] * MAXLEN^(str_len - 1) + ... + str[1] * MAXLEN + str[0]
        my_char = msg[j];
        mpz_mul_ui(integer_msg, integer_msg, (unsigned long)MAXLEN);
        mpz_add_ui(integer_msg, integer_msg, (unsigned long)my_char);

    }


}


void encrypt(mpz_t c, mpz_t message, public_key publicKey) {
    //c = message^2 mod n.
    mpz_t pow;
    mpz_init(pow);
    mpz_set_ui(pow,2);
    mpz_powm(c, message, pow,publicKey.n);

    return;
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

        mpz_mod_ui(int_character, tmp_converted_msg, (unsigned long)MAXLEN);//int_character=tmp_converted_msg mod MAXLEN
        mpz_sub(tmp_converted_msg, tmp_converted_msg, int_character);//int_character - tmp_converted_msg
        mpz_tdiv_q_ui(tmp_converted_msg, tmp_converted_msg, (unsigned long)MAXLEN);//tmp_converted_msg - tmp_converted_msg * (unsigned long)MAXLEN


        first_msg[i] = mpz_get_ui(int_character);

    }

    first_msg[str_len] = '\0';

    mpz_clear(max_int);
    mpz_clear(int_character);
    mpz_clear(tmp_converted_msg);

}



void findCorrectRoot(mpz_t msg,mpz_t root1,mpz_t root2,mpz_t root3,mpz_t root4) {
    char first_msg[250];

    if (mpz_cmp(msg, root1)==0) {
        printf("\nThe correct root is -x\n");
        convert_integer_to_msg(first_msg, root1);
        printf("\nSo the first message is: %s", first_msg);

    } else if (mpz_cmp(msg, root2)==0) {

        printf("\nThe correct root is -x\n");
        convert_integer_to_msg(first_msg, root2);
        printf("\nSo the first message is: %s", first_msg);

    } else if (mpz_cmp(msg, root3)==0) {
        printf("\nThe correct root is y\n");
        convert_integer_to_msg(first_msg, root3);
        printf("\nSo the first message is: %s", first_msg);

    } else if (mpz_cmp(msg, root4)==0) {
        printf("\nThe correct root is -y\n");
        convert_integer_to_msg(first_msg, root4);
        printf("\nSo the message is: %s", first_msg);

    } else {
        printf("\nThe first message is: ");
        convert_integer_to_msg(first_msg, msg);
        printf("%s", first_msg);

    }

}

void decrypt(mpz_t c,mpz_t root1,mpz_t root2,mpz_t root3,mpz_t root4,public_key publicKey,private_key privateKey) {


    int flag=0;
    mpz_t tmp_p,tmp_q,a,b,r,s,p1,q1,aps,bqr;
    mpz_t d,x,y,x1,x2,y1,y2,temp_q1;
    mpz_t qb,a_qb,temp;
    mpz_t qx1,x2_qx1;
    mpz_t qy1,y2_qy1;

    mpz_inits(tmp_p,tmp_q,a,b,p1,q1,r,s,aps,bqr, NULL);
    mpz_init(x);
    mpz_init(y);
    mpz_init(d);
    mpz_init(temp);
    mpz_init(temp_q1);
    mpz_init(x1);
    mpz_init(x2);
    mpz_init(y1);
    mpz_init(y2);
    mpz_init(qb);
    mpz_init(a_qb);
    mpz_init(qx1);
    mpz_init(qy1);
    mpz_init(x2_qx1);
    mpz_init(y2_qy1);
    //Note (finding square roots of c modulo n = pq when p ≡ q ≡ 3 (mod 4))

    mpz_set(tmp_p,privateKey.p);
    mpz_set(tmp_q,privateKey.q);

     printf("\n\nCreate a,b in order that a*p + b*q = 1:\n");
     //Algorithm Extended Euclidean algorithm
    if(mpz_cmp(tmp_q,tmp_p)>0) {//Συγκρινω τα p kai q

        flag=1;
        mpz_set(temp,tmp_q);
        mpz_set(tmp_q,tmp_p);
        mpz_set(tmp_p,temp);
     }

    if(mpz_cmp_ui(tmp_q,0)==0) {

        mpz_set(d,tmp_p);
        mpz_set_ui(x,1);
        mpz_set_ui(y,0);
    } else {
        mpz_set_ui(x2,1);
        mpz_set_ui(x1,0);
        mpz_set_ui(y1,1);
        mpz_set_ui(y2,0);

        while(mpz_cmp_ui(tmp_q,0)>0) {
            mpz_tdiv_q(temp_q1,tmp_p,tmp_q);
            mpz_mul(qb,temp_q1,tmp_q);
            mpz_sub(a_qb,tmp_p,qb);
            mpz_set(r,a_qb);
            mpz_mul(qx1,temp_q1,x1);
            mpz_sub(x2_qx1,x2,qx1);
            mpz_set(x,x2_qx1);
            mpz_mul(qy1,temp_q1,y1);
            mpz_sub(y2_qy1,y2,qy1);
            mpz_set(y,y2_qy1);
            mpz_set(tmp_p,tmp_q);
            mpz_set(tmp_q,r);
            mpz_set(x2,x1);
            mpz_set(x1,x);
            mpz_set(y2,y1);
            mpz_set(y1,y);
        }
    }
    mpz_set(d,tmp_p);
    mpz_set(x,x2);
    mpz_set(y,y2);

    if(flag==1){
        mpz_set(b,x);
        mpz_set(a,y);
    }else{

        mpz_set(b,y);
        mpz_set(a,x);

    }


    printf("a= %s\n\n", mpz_get_str(NULL, 0, a));
    printf("b= %s\n\n", mpz_get_str(NULL, 0, b));

    //r = c^(p+1)/4 mod p και s = c^(q+1)/4 mod q.
    printf("\nCreate  r = c^(p+1)/4 mod p and s = c^(q+1)/4 mod q:\n");

    // (p+1)/4
    mpz_set(p1,privateKey.p);
    mpz_add_ui(p1,p1,1);
    mpz_div_ui(p1,p1,4);

    //(q+1)/4
    mpz_set(q1,privateKey.q);
    mpz_add_ui(q1,q1,1);
    mpz_div_ui(q1,q1,4);


    //c^(p+1)/4
    mpz_powm(r,c,p1,privateKey.p);

    //c^(q+1)/4
    mpz_powm(s,c,q1,privateKey.q);


    printf("r= %s\n\n", mpz_get_str(NULL, 0, r));
    printf("s= %s\n\n", mpz_get_str(NULL, 0, s));


     printf("\n\nCreate 4 roots (x, -x, y, -y): \n");
    //x = (aps + bqr) mod n

    mpz_set(aps,a);
    mpz_mul(aps,aps,privateKey.p);
    mpz_mul(aps,aps,s);


    mpz_set(bqr,b);
    mpz_mul(bqr,bqr,privateKey.q);
    mpz_mul(bqr,bqr,r);

    //x = (aps + bqr) mod n
    mpz_set(root1,aps);
    mpz_add(root1,root1,bqr);
    mpz_mod(root1,root1,publicKey.n);
    printf("x= %s\n\n", mpz_get_str(NULL, 0, root1));


    mpz_set(root2,publicKey.n);
    mpz_sub(root2,root2,root1);
    printf("-x= %s\n\n", mpz_get_str(NULL, 0, root2));

    mpz_set(root3,aps);
    mpz_sub(root3,root3,bqr);
    mpz_mod(root3,root3,publicKey.n);
    printf("y= %s\n\n", mpz_get_str(NULL, 0, root3));


    mpz_set(root4,publicKey.n);
    mpz_sub(root4,root4,root2);
    printf("-y= %s\n\n", mpz_get_str(NULL, 0, root4));


    mpz_clears(tmp_p,tmp_q,a,b,p1,q1,r,s,aps,bqr, NULL);
    mpz_clear(temp);
    mpz_clear(d);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(x1);
    mpz_clear(x2);
    mpz_clear(y1);
    mpz_clear(y2);
    mpz_clear(temp_q1);
    mpz_clear(r);
    mpz_clear(qb);
    mpz_clear(a_qb);
    mpz_clear(qx1);
    mpz_clear(x2_qx1);
    mpz_clear(qy1);
    mpz_clear(y2_qy1);
    return;
}


void display_encrypt_decrypt_message(char* msg,public_key publicKey,private_key privateKey) {

    mpz_t message;
    mpz_t encrypted,root1,root2,root3,root4;
    mpz_inits(encrypted,root1,root2,root3,root4, NULL);
    convert_msg_to_integer(message,msg);
    encrypt(encrypted,message,publicKey);
    decrypt(encrypted,root1,root2,root3,root4,publicKey,privateKey);


    printf("----------------------------------------------------\n");
    printf("The first message is : %s\n", msg);
    printf("The m from message is: %s\n", mpz_get_str(NULL, 0, message));
    printf("The (c) encrypted message: %s\n", mpz_get_str(NULL, 0, encrypted));
    printf("Decryption: \n");

    findCorrectRoot(message,root1,root2,root3,root4);
    printf("\n----------------------------------------------------\n");

    //Clear
    mpz_clears(encrypted,root1,root2,root3,root4,message,NULL);
}
int main() {

    private_key privateKey;
    public_key publicKey;

    mpz_init(publicKey.n);

    mpz_init(privateKey.p);
    mpz_init(privateKey.q);


    createKeysRabin(&privateKey,&publicKey);

    display_encrypt_decrypt_message("This is a message for testing",publicKey,privateKey);




    return 0;
}

