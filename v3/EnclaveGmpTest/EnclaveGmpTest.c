/*

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "EnclaveGmpTest_t.h"
#include <sgx_tgmp.h>
#include <sgx_trts.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "serialize.h"
#define BUFSIZ 100

#define SIZE 1000
#define NUM_POINT_ADDITIONS 100
#define NUM_SCALER_MULTIPLICATIONS 100
#define NUM_HASHES 100
#define USERS 4
#define FAULTS 1
#define HASH_STR "10000"
#define ARRAY_PLACEHOLDER 20000

struct Elliptic_Curve {
        mpz_t a;
        mpz_t b;
        mpz_t p;
};

struct Point {
        mpz_t x;
        mpz_t y;
};

struct user_struct {
    mpz_t key;
    mpz_t message;
    int id;
    struct Point point1;
    struct Point point2;
    struct Point ciphertext;
};

struct Elliptic_Curve EC;
struct user_struct user_array[ARRAY_PLACEHOLDER];
struct Point Aggregation_Point;
struct Point temp_user_point;

char *result;
size_t len_result= 0;
unsigned long mpz_bit_count = 256;

/*
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
*/


void Point_Doubling(struct Point P, struct Point *R)
{
        mpz_t slope, temp;
        mpz_init(temp);
        mpz_init(slope);

        if(mpz_cmp_ui(P.y, 0) != 0) {
                mpz_mul_ui(temp, P.y, 2);
                mpz_invert(temp, temp, EC.p);
                mpz_mul(slope, P.x, P.x);
                mpz_mul_ui(slope, slope, 3);
                mpz_add(slope, slope, EC.a);
                mpz_mul(slope, slope, temp);
                mpz_mod(slope, slope, EC.p);
                mpz_mul(R->x, slope, slope);
                mpz_sub(R->x, R->x, P.x);
                mpz_sub(R->x, R->x, P.x);
                mpz_mod(R->x, R->x, EC.p);
                mpz_sub(temp, P.x, R->x);
                mpz_mul(R->y, slope, temp);
                mpz_sub(R->y, R->y, P.y);
                mpz_mod(R->y, R->y, EC.p);
        } else {
                mpz_set_ui(R->x, 0);
                mpz_set_ui(R->y, 0);
        }
        mpz_clear(temp);
        mpz_clear(slope);
}

void Point_Addition(struct Point P, struct Point Q, struct Point *R)
{
        mpz_mod(P.x, P.x, EC.p);
        mpz_mod(P.y, P.y, EC.p);
        mpz_mod(Q.x, Q.x, EC.p);
        mpz_mod(Q.y, Q.y, EC.p);

        if(mpz_cmp_ui(P.x, 0) == 0 && mpz_cmp_ui(P.y, 0) == 0) {
                mpz_set(R->x, Q.x);
                mpz_set(R->y, Q.y);
                return;
        }

        if(mpz_cmp_ui(Q.x, 0) == 0 && mpz_cmp_ui(Q.y, 0) == 0) {
                mpz_set(R->x, P.x);
                mpz_set(R->y, P.y);
                return;
        }

        mpz_t temp;
        mpz_init(temp);

        if(mpz_cmp_ui(Q.y, 0) != 0) {
                mpz_sub(temp, EC.p, Q.y);
                mpz_mod(temp, temp, EC.p);
        } else
                mpz_set_ui(temp, 0);


        if(mpz_cmp(P.y, temp) == 0 && mpz_cmp(P.x, Q.x) == 0) {
                mpz_set_ui(R->x, 0);
                mpz_set_ui(R->y, 0);
                mpz_clear(temp);
                return;
        }

        if(mpz_cmp(P.x, Q.x) == 0 && mpz_cmp(P.y, Q.y) == 0)    {
                Point_Doubling(P, R);

                mpz_clear(temp);
                return;
        } else {
                mpz_t slope;
                mpz_init_set_ui(slope, 0);

                mpz_sub(temp, P.x, Q.x);
                mpz_mod(temp, temp, EC.p);
                mpz_invert(temp, temp, EC.p);
                mpz_sub(slope, P.y, Q.y);
                mpz_mul(slope, slope, temp);
                mpz_mod(slope, slope, EC.p);
                mpz_mul(R->x, slope, slope);
                mpz_sub(R->x, R->x, P.x);
                mpz_sub(R->x, R->x, Q.x);
                mpz_mod(R->x, R->x, EC.p);
                mpz_sub(temp, P.x, R->x);
                mpz_mul(R->y, slope, temp);
                mpz_sub(R->y, R->y, P.y);
                mpz_mod(R->y, R->y, EC.p);

                mpz_clear(temp);
                mpz_clear(slope);
                return;
        }
}

void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m)
{
        struct Point Q, T;
        mpz_init(Q.x); mpz_init(Q.y);
        mpz_init(T.x); mpz_init(T.y);
        long no_of_bits, loop;

        no_of_bits = mpz_sizeinbase(m, 2);
        mpz_set_ui(R->x, 0);
        mpz_set_ui(R->y, 0);
        if(mpz_cmp_ui(m, 0) == 0)
                return;

        mpz_set(Q.x, P.x);
        mpz_set(Q.y, P.y);
        if(mpz_tstbit(m, 0) == 1){
                mpz_set(R->x, P.x);
                mpz_set(R->y, P.y);
        }

        for(loop = 1; loop < no_of_bits; loop++) {
                mpz_set_ui(T.x, 0);
                mpz_set_ui(T.y, 0);
                Point_Doubling(Q, &T);

                mpz_set(Q.x, T.x);
                mpz_set(Q.y, T.y);
                mpz_set(T.x, R->x);
                mpz_set(T.y, R->y);
                if(mpz_tstbit(m, loop))
                        Point_Addition(T, Q, R);
        }

        mpz_clear(Q.x); mpz_clear(Q.y);
        mpz_clear(T.x); mpz_clear(T.y);
}



void *(*gmp_realloc_func)(void *, size_t, size_t);
void (*gmp_free_func)(void *, size_t);

void *reallocate_function(void *, size_t, size_t);
void free_function(void *, size_t);

void e_calc_pi (mpf_t *pi, uint64_t digits);


void tgmp_init()
{
	result= NULL;
	len_result= 0;

	mp_get_memory_functions(NULL, &gmp_realloc_func, &gmp_free_func);
	mp_set_memory_functions(NULL, &reallocate_function, &free_function);
}

void free_function (void *ptr, size_t sz)
{
	if ( sgx_is_within_enclave(ptr, sz) ) gmp_free_func(ptr, sz);
	else abort();
}

void *reallocate_function (void *ptr, size_t osize, size_t nsize)
{
	if ( ! sgx_is_within_enclave(ptr, osize) ) abort();

	return gmp_realloc_func(ptr, osize, nsize);
}


int e_get_result(char *str, size_t len)
{
	/* Make sure the application doesn't ask for more bytes than 
	 * were allocated for the result. */

	if ( len > len_result ) return 0;

	/*
	 * Marshal our result out of the enclave. Make sure the destination
	 * buffer is completely outside the enclave, and that what we are
	 * copying is completely inside the enclave.
	 */

	if ( result == NULL || str == NULL || len == 0 ) return 0;

	if ( ! sgx_is_within_enclave(result, len) ) return 0;

	if ( sgx_is_outside_enclave(str, len+1) ) { /* Include terminating NULL */
		strncpy(str, result, len); 
		str[len]= '\0';

		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;

		return 1;
	}

	return 0;
}	

size_t check_Setup1(int id, int choice){

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}

	switch(choice){
        	case 0:
                	result = mpz_serialize(user_array[id].point1.x);
                	if ( result == NULL ) return 0;
        		len_result = strlen(result);
        		return len_result;
		
		case 1:
			result = mpz_serialize(user_array[id].point1.y);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;
                
		case 2:
			result = mpz_serialize(user_array[id].point2.x);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;
                
		case 3:
			result = mpz_serialize(user_array[id].point2.y);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;
                
		case 4:
			result = mpz_serialize(user_array[id].ciphertext.x);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;
                
		case 5:
			result = mpz_serialize(user_array[id].ciphertext.y);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;
                
		case 6:
			result = mpz_serialize(user_array[id].key);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;

		case 7:
                        result = mpz_serialize(user_array[id].message);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;

		case 8:
                        result = mpz_serialize(Aggregation_Point.x);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;

		case 9:
                        result = mpz_serialize(Aggregation_Point.y);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;

		case 10:
                        result = mpz_serialize(temp_user_point.x);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;

                case 11:
                        result = mpz_serialize(temp_user_point.y);
                        if ( result == NULL ) return 0;
                        len_result = strlen(result);
                        return len_result;



        }

}

int check_Setup2(char *str, size_t len){

	if ( len > len_result ) return 0;

	if ( result == NULL || str == NULL || len == 0 ) return 0;

	if ( ! sgx_is_within_enclave(result, len) ) return 0;

	if ( sgx_is_outside_enclave(str, len+1) ) { /* Include terminating NULL */

		strncpy(str, result, len); 
		str[len]= '\0';

		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;

		return 1;
	}

	return 0;
}

void do_Setup(int num){

	mpz_init(EC.a);
        mpz_init(EC.b);
        mpz_init(EC.p);

        struct Point P, temp_point;
        mpz_init2(P.x, mpz_bit_count);
        mpz_init2(P.y, mpz_bit_count);
	mpz_init2(temp_point.x, mpz_bit_count);
        mpz_init2(temp_point.y, mpz_bit_count);

	
	mpz_set_str(EC.p, "17", 10);
	mpz_set_str(EC.a, "2", 10);
	mpz_set_str(EC.b, "2", 10);

	//Use (5,1) as generator
    	mpz_set_str(P.x, "5", 10);
	mpz_set_str(P.y, "1", 10);
	

	int users = USERS;

	
	//Assume hash maps time stamp to point (5, 1)
	mpz_set_str(temp_point.x, "5", 10);
	mpz_set_str(temp_point.y, "1", 10);
	

       	mpz_t temp_rand;
       	mpz_t rand_max;
       	mpz_init2(temp_rand, mpz_bit_count);
       	mpz_init2(rand_max, mpz_bit_count);

       	mpz_t aggregator_key_accumulator;
       	mpz_init2(aggregator_key_accumulator, mpz_bit_count);

       	mpz_set_si(rand_max, 19);
       	mpz_set_si(aggregator_key_accumulator, 0);

       	unsigned long int tmp_seed = 1;

       	gmp_randstate_t rand_state;
       	gmp_randinit_mt(rand_state);
       	gmp_randseed_ui(rand_state, tmp_seed);

	//Generate user keys etc. in TEE
	for(int i = 0; i < users; i++){

		mpz_init2(user_array[i].key, mpz_bit_count);
		
		if(i < users - 1){
			mpz_urandomm(temp_rand, rand_state, rand_max);
			mpz_add(aggregator_key_accumulator, aggregator_key_accumulator, temp_rand);
		}
		else{
		
			mpz_mod(aggregator_key_accumulator, aggregator_key_accumulator, rand_max);
			mpz_sub(temp_rand, rand_max, aggregator_key_accumulator);
		}
                
		mpz_set(user_array[i].key, temp_rand);
		//mpz_set_si(user_array[i].key, 0);

		mpz_init2(user_array[i].message, mpz_bit_count);
		mpz_set_si(user_array[i].message, 0);

		mpz_init2(user_array[i].point1.x, mpz_bit_count);
                mpz_init2(user_array[i].point1.y, mpz_bit_count);
                mpz_init2(user_array[i].point2.x, mpz_bit_count);
                mpz_init2(user_array[i].point2.y, mpz_bit_count);

                Scalar_Multiplication(temp_point, &user_array[i].point2, user_array[i].key);
                Scalar_Multiplication(P, &user_array[i].point1, user_array[i].message);
                mpz_init2(user_array[i].ciphertext.x, mpz_bit_count);
                mpz_init2(user_array[i].ciphertext.y, mpz_bit_count);
                Point_Addition(user_array[i].point1, user_array[i].point2, &user_array[i].ciphertext);
        }	

	//temp_user_point is used to store data passed from user during ecall and Aggregation_Point is where we store the aggregation result
	mpz_init2(Aggregation_Point.x, mpz_bit_count);
	mpz_init2(Aggregation_Point.y, mpz_bit_count);

	mpz_init2(temp_user_point.x, mpz_bit_count);
        mpz_init2(temp_user_point.y, mpz_bit_count);

	mpz_set_str(temp_user_point.x, "5", 10);
        mpz_set_str(temp_user_point.y, "1", 10);

	Scalar_Multiplication(temp_user_point, &Aggregation_Point, user_array[users-1].key);

	return;
}

//struct Point Agg_temp;

void do_Point_Addition(char *str_a, char *str_b, int id){

	//Read in data from outside TEE, deserialize, and either aggregate or perform fault recovery
	struct Point Agg_temp;
	mpz_init2(Agg_temp.x, mpz_bit_count);
	mpz_init2(Agg_temp.y, mpz_bit_count);
	mpz_set(Agg_temp.x, Aggregation_Point.x);
	mpz_set(Agg_temp.y, Aggregation_Point.y);


        if ( mpz_deserialize(&temp_user_point.x, str_a) == -1 ) return 0;
        if ( mpz_deserialize(&temp_user_point.y, str_b) == -1 ) return 0;

	//if(fault == 0){
        Point_Addition(temp_user_point, Agg_temp, &Aggregation_Point);
	//}

	//else{
	//	Point_Addition(user_array[id].ciphertext, Agg_temp, &Aggregation_Point);
	//}

	return;
}

void do_Point_Addition_Recovery(int id){
        
	struct Point Agg_temp;
        mpz_init2(Agg_temp.x, mpz_bit_count);
        mpz_init2(Agg_temp.y, mpz_bit_count);
        mpz_set(Agg_temp.x, Aggregation_Point.x);
        mpz_set(Agg_temp.y, Aggregation_Point.y);

	Point_Addition(user_array[id].ciphertext, Agg_temp, &Aggregation_Point);

	return;
}

void do_Aggregation_Result(int *sum, uint32_t len)
{
	struct Point Placeholder, P;
	mpz_t m;

	mpz_init2(Placeholder.x, mpz_bit_count);
        mpz_init2(Placeholder.y, mpz_bit_count);
	mpz_init2(P.x, mpz_bit_count);
        mpz_init2(P.y, mpz_bit_count);
	mpz_init2(m, mpz_bit_count);

	mpz_set_str(P.x, "5", 10);
        mpz_set_str(P.y, "1", 10);

	//Determine aggregation value
	for(long int i = 0; i < SIZE; i++){
                
                mpz_set_si(m, i);
        	Scalar_Multiplication(P, &Placeholder, m);

		if(mpz_cmp(Placeholder.x, Aggregation_Point.x) == 0 && mpz_cmp(Placeholder.y, Aggregation_Point.y) == 0){
			*sum = i;
			return;
        	 }
	}

	*sum = -1;	
        return;
}



size_t e_mpz_add(char *str_a, char *str_b)
{
	mpz_t a, b, c;
	mpz_inits(a, b, c, NULL);

	/*
	 * Marshal untrusted values into the enclave so we don't accidentally
	 * leak secrets to untrusted memory.
	 *
	 * This is overkill for the trivial example in this function, but
	 * it's best to develop good coding habits.
	 */

	if ( str_a == NULL || str_b == NULL ) return 0;

	/* Clear the last, serialized result */

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}

	mpz_inits(a, b, c, NULL);

	/* Deserialize */

	if ( mpz_deserialize(&a, str_a) == -1 ) return 0;
	if ( mpz_deserialize(&b, str_b) == -1 ) return 0;

	mpz_add(c, a, b);

	/* Serialize the result */

	result= mpz_serialize(c);
	if ( result == NULL ) return 0;

	len_result= strlen(result);
	return len_result;
}

size_t e_mpz_mul(char *str_a, char *str_b)
{
	mpz_t a, b, c;

	/* Marshal untrusted values into the enclave. */

	if ( str_a == NULL || str_b == NULL ) return 0;

	/* Clear the last, serialized result */

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}

	mpz_inits(a, b, c, NULL);

	/* Deserialize */

	if ( mpz_deserialize(&a, str_a) == -1 ) return 0;
	if ( mpz_deserialize(&b, str_b) == -1 ) return 0;

	mpz_mul(c, a, b);

	/* Serialize the result */

	result= mpz_serialize(c);
	if ( result == NULL ) return 0;

	len_result= strlen(result);
	return len_result;
}

size_t e_mpz_div(char *str_a, char *str_b)
{
	mpz_t a, b, c;

	/* Marshal untrusted values into the enclave */

	if ( str_a == NULL || str_b == NULL ) return 0;

	/* Clear the last, serialized result */

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}

	mpz_inits(a, b, c, NULL);

	/* Deserialize */

	if ( mpz_deserialize(&a, str_a) == -1 ) return 0;
	if ( mpz_deserialize(&b, str_b) == -1 ) return 0;

	mpz_div(c, a, b);

	/* Serialize the result */

	result= mpz_serialize(c);
	if ( result == NULL ) return 0;

	len_result= strlen(result);
	return len_result;
}

size_t e_mpf_div(char *str_a, char *str_b, int digits)
{
	mpz_t a, b;
	mpf_t fa, fb, fc;

	/* Marshal untrusted values into the enclave */

	if ( str_a == NULL || str_b == NULL ) return 0;

	/* Clear the last, serialized result */

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}

	mpz_inits(a, b, NULL);
	mpf_inits(fa, fb, fc, NULL);

	/* Deserialize */

	if ( mpz_deserialize(&a, str_a) == -1 ) return 0;
	if ( mpz_deserialize(&b, str_b) == -1 ) return 0;

	mpf_set_z(fa, a);
	mpf_set_z(fb, b);

	mpf_div(fc, fa, fb);


	/* Serialize the result */

	result= mpf_serialize(fc, digits);
	if ( result == NULL ) return 0;

	len_result= strlen(result);
	return len_result;
}

/* Use the Chudnovsky equation to rapidly estimate pi */

#define DIGITS_PER_ITERATION 14.1816 /* Roughly */

mpz_t c3, c4, c5;
int pi_init= 0;

size_t e_pi (uint64_t digits)
{
	mpf_t pi;

	/* Clear the last, serialized result */

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}

	/*
	 * Perform our operations on a variable that's located in the enclave,
	 * then marshal the final value out of the enclave.
	 */

	mpf_init(pi);

	e_calc_pi(&pi, digits+1);

	/* Marshal our result to untrusted memory */

	mpf_set_prec(pi, mpf_get_prec(pi));

	result= mpf_serialize(pi, digits+1);
	if ( result == NULL ) return 0;

	len_result= strlen(result);
	return len_result;
}

void e_calc_pi (mpf_t *pi, uint64_t digits)
{
	uint64_t k, n;
	mp_bitcnt_t precision;
	static double bits= log2(10);
	mpz_t kf, kf3, threekf, sixkf, z1, z2, c4k, c5_3k;
	mpf_t C, sum, div, f2;

	n= (digits/DIGITS_PER_ITERATION)+1;
	precision= (digits * bits)+1;

	mpf_set_default_prec(precision);

	/* Re-initialize the pi variable to use our new precision */

	mpf_set_prec(*pi, precision);

	/*

		426880 sqrt(10005)    inf (6k)! (13591409+545140134k)
		------------------- = SUM ---------------------------
		         pi           k=0   (3k)!(k!)^3(-640320)^3k

		C / pi = SUM (6k)! * (c3 + c4*k) / (3k)!(k!)^3(c5)^3k

		C / pi = SUM f1 / f2

		pi = C / sum

	*/

	mpz_inits(sixkf, z1, z2, kf, kf3, threekf, c4k, c5_3k, NULL);
	mpf_inits(C, sum, div, f2, NULL);

	/* Calculate 'C' */

	mpf_sqrt_ui(C, 10005);
	mpf_mul_ui(C, C, 426880);

	if ( ! pi_init ) {
		/* Constants needed in 'sum'. */

		mpz_inits(c3, c4, c5, NULL);

		mpz_set_ui(c3, 13591409);
		mpz_set_ui(c4, 545140134);
		mpz_set_si(c5, -640320);

		pi_init= 1;
	}


	mpf_set_ui(sum, 0);

	for (k= 0; k< n; ++k) {
		/* Numerator */
		mpz_fac_ui(sixkf, 6*k);
		mpz_mul_ui(c4k, c4, k);
		mpz_add(c4k, c4k, c3);
		mpz_mul(z1, c4k, sixkf);
		mpf_set_z(div, z1);

		/* Denominator */
		mpz_fac_ui(threekf, 3*k);
		mpz_fac_ui(kf, k);
		mpz_pow_ui(kf3, kf, 3);
		mpz_mul(z2, threekf, kf3);
		mpz_pow_ui(c5_3k, c5, 3*k);
		mpz_mul(z2, z2, c5_3k);

		/* Divison */

		mpf_set_z(f2, z2);
		mpf_div(div, div, f2);

		/* Sum */

		mpf_add(sum, sum, div);
	}

	mpf_div(*pi, C, sum);

	mpf_clears(div, sum, f2, NULL);
}

