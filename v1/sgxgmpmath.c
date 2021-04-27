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

#include <sgx_urts.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "EnclaveGmpTest_u.h"
#include "create_enclave.h"
#include "sgx_detect.h"
#include "serialize.h"
#include <time.h>

#define ENCLAVE_NAME "EnclaveGmpTest.signed.so"

#define SIZE 1000
#define NUM_POINT_ADDITIONS 100
#define NUM_SCALER_MULTIPLICATIONS 100
#define NUM_HASHES 100
#define USERS 4
#define FAULTS 1
#define HASH_STR "10000"
#define SIZE 1000
#define ARRAY_PLACEHOLDER 2000

struct Elliptic_Curve {
        mpz_t a;
        mpz_t b;
        mpz_t p;
};

struct Point {
        mpz_t x;
        mpz_t y;
};

struct user_struct_out {
    mpz_t key;
    mpz_t message;
    int id;
    struct Point point1;
    struct Point point2;
    struct Point ciphertext;
};

struct Elliptic_Curve EC;

const char* getfield(char* line, int num){
	const char* tok;
        for (tok = strtok(line, ",");
                tok && *tok;
                tok = strtok(NULL, ",\n"))
        {
           if (!--num)
               return tok;
        }
        return NULL;
}

//https://github.com/masterzorag/ec_gmp/blob/master/ec_gmp_p_mul.c
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

//https://github.com/intel/sgx-gmp-demo
int main (int argc, char *argv[])
{
	sgx_launch_token_t token= { 0 };
	sgx_enclave_id_t eid= 0;
	sgx_status_t status;
	int updated= 0;
	int rv= 0;
	unsigned long support;
	mpz_t a, b, c;
	mpf_t fc;
	char *str_a, *str_b, *str_c, *str_fc;
	size_t len;
	int digits= 12; 


#ifndef SGX_HW_SIM
	support= get_sgx_support();
	if ( ! SGX_OK(support) ) {
		sgx_support_perror(support);
		return 1;
	}
#endif

	status= sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG,
		 &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) {
			fprintf(stderr, "sgx_create_enclave: %s: file not found\n",
				ENCLAVE_NAME);
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		} else {
			fprintf(stderr, "%s: 0x%04x\n", ENCLAVE_NAME, status);
		}
		return 1;
	}

	fprintf(stderr, "Enclave launched\n");

	status= tgmp_init(eid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL error: 0x%04x\n", status);
		return 1;
	}

	fprintf(stderr, "libtgmp initialized\n");

	FILE* stream = fopen("WELL-00001_20170317140005.csv", "r");
  
	mpz_init(EC.a);
        mpz_init(EC.b);
        mpz_init(EC.p);

        struct Point P, temp_point;
        mpz_init(P.x);
        mpz_init(P.y);
	mpz_init(temp_point.x);
        mpz_init(temp_point.y);

	mpz_set_str(EC.p, "17", 10);
	mpz_set_str(EC.a, "2", 10);
	mpz_set_str(EC.b, "2", 10);

	//Generator
        mpz_set_str(P.x, "5", 10);
        mpz_set_str(P.y, "1", 10);

	//Hash point
        mpz_set_str(temp_point.x, "5", 10);
        mpz_set_str(temp_point.y, "1", 10);


	int users = USERS, faults = FAULTS, counter = 0;
	long int plaintext = 0;
        struct user_struct_out user_array_out[ARRAY_PLACEHOLDER];
        char line[1024];

        while (fgets(line, 1024, stream) && counter < (users)){
            char* tmp = strdup(line);
	    int plaintext = atol(getfield(tmp, 3));
	    mpz_init(user_array_out[counter].message);
	    mpz_set_si(user_array_out[counter].message, plaintext);
            counter++;
        }

	clock_t begin = clock();

	mpz_t temp_rand;
       	mpz_t rand_max;
       
       	mpz_init(temp_rand);
       	mpz_init(rand_max);

	mpz_t aggregator_key_accumulator;
       	mpz_init(aggregator_key_accumulator);

       	mpz_set_si(rand_max, 19);
       	mpz_set_si(aggregator_key_accumulator, 0);

       	unsigned long int tmp_seed = 1;

       	gmp_randstate_t rand_state;
	gmp_randinit_mt(rand_state);
       	gmp_randseed_ui(rand_state, tmp_seed); 
       
	//Generate and assign user values
       	for(int i = 0; i < users; i++){
       		

      		mpz_init(user_array_out[i].key);
          	
		if(i < users - 1){
                        mpz_urandomm(temp_rand, rand_state, rand_max);
                        mpz_add(aggregator_key_accumulator, aggregator_key_accumulator, temp_rand);
                }
                else{

                        mpz_mod(aggregator_key_accumulator, aggregator_key_accumulator, rand_max);
                        mpz_sub(temp_rand, rand_max, aggregator_key_accumulator);
                }
	
		
		mpz_set(user_array_out[i].key, temp_rand);	      
		//mpz_set_si(user_array_out[i].key, 0);

		mpz_init(user_array_out[i].point1.x);
		mpz_init(user_array_out[i].point1.y);
		mpz_init(user_array_out[i].point2.x);
                mpz_init(user_array_out[i].point2.y);
		
		Scalar_Multiplication(temp_point, &user_array_out[i].point2, user_array_out[i].key);
		Scalar_Multiplication(P, &user_array_out[i].point1, user_array_out[i].message);
		
		mpz_init(user_array_out[i].ciphertext.x);
		mpz_init(user_array_out[i].ciphertext.y);
		Point_Addition(user_array_out[i].point1, user_array_out[i].point2, &user_array_out[i].ciphertext);

	}

	/*	
	//Print user data for debugging
	for(int i = 0; i < users; i++){
		
		printf("\nUser %i: \n", i);
		printf("key: ");
    		mpz_out_str(stdout, 10, user_array_out[i].key);
    		printf("\nmessage: ");
                mpz_out_str(stdout, 10, user_array_out[i].message);
		printf("\npoint1: (");
		mpz_out_str(stdout, 10, user_array_out[i].point1.x);
		printf(", ");
    		mpz_out_str(stdout, 10, user_array_out[i].point1.y);
    		printf(")\n");

		printf("point2: (");
                mpz_out_str(stdout, 10, user_array_out[i].point2.x);
                printf(", ");
                mpz_out_str(stdout, 10, user_array_out[i].point2.y);
                printf(")\n");

		printf("ciphertext: (");
                mpz_out_str(stdout, 10, user_array_out[i].ciphertext.x);
                printf(", ");
                mpz_out_str(stdout, 10, user_array_out[i].ciphertext.y);
                printf(")\n\n");

	}
	*/

	//Initialize TEE with secret keys etc.
	do_Setup(eid, users);

	clock_t end = clock();
        double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
        printf("Setup Time: %f seconds\n", time_spent);

/*	
 	//Print values in Enclave for debugging
	printf("About to print values stored in Enclave\n");	
	for(int j = 7; j < 8; j++){

		for(int i = 0; i < users; i++){
			// note we need to call check_Setup1 and then check_Setup2 to recover debugging values
			mpz_t testingprint;
        		mpz_init(testingprint);
			size_t len_of_buf;
			status = check_Setup1(eid, &len, i, j);
			char* buf_to_pass = malloc(len_of_buf+1);
			status = check_Setup2(eid, &rv, buf_to_pass, len);
			mpz_deserialize(&testingprint, buf_to_pass);
			
			switch(j){
				case 0:
					gmp_printf("User %i point1.x is %Zd\n", i, testingprint);
					break;
				case 1:
					gmp_printf("User %i point1.y is %Zd\n", i, testingprint);
					break;
				case 2:
					gmp_printf("User %i point2.x is %Zd\n", i, testingprint);
					break;
				case 3:
					gmp_printf("User %i point2.y is %Zd\n", i, testingprint);
					break;
				case 4:
					gmp_printf("User %i ciphertext.x is %Zd\n", i, testingprint);
					break;
				case 5:
					gmp_printf("User %i ciphertext.y is %Zd\n", i, testingprint);
					break;
				case 6:
					gmp_printf("User %i key is %Zd\n", i, testingprint);
					break;
				case 7:
                                        gmp_printf("User %i message is %Zd\n", i, testingprint);
					break;
			}
			
		}
		printf("\n");
	}	
*/	


	begin = clock();


	/*
	//Print intermediate numbers for debugging
	printf("\n\nFirst test of intermediate numbers\n");
	mpz_t testingprint;
        mpz_init(testingprint);
        size_t len_of_buf;
	char* buf_to_pass = malloc(len_of_buf+1);
        
	for(int j = 8; j < 10; j++){

	status = check_Setup1(eid, &len, 0, j);
        status = check_Setup2(eid, &rv, buf_to_pass, len);
        mpz_deserialize(&testingprint, buf_to_pass);
        gmp_printf("Point is %Zd\n", testingprint);

	}
	//End test
	*/

	for(int i = 0; i < users - faults - 1; i++){
		//Serialize user data and send into TEE for aggregation;
		str_a = mpz_serialize(user_array_out[i].ciphertext.x);
        	str_b = mpz_serialize(user_array_out[i].ciphertext.y);
		do_Point_Addition(eid, str_a, str_b, i, 0);
	
		/*	
		//Test
		printf("\n");
		for(int j = 8; j < 10; j++){

 		       status = check_Setup1(eid, &len, 0, j);
        		status = check_Setup2(eid, &rv, buf_to_pass, len);
        		mpz_deserialize(&testingprint, buf_to_pass);
        		gmp_printf("Point is %Zd\n", testingprint);

        	}
		
		//Finish test
		*/
	}

	clock_t fault_begin = clock();

	for(int i = (users - faults - 1); i < users - 1; i++){
		//Have TEE perform fault recovery
		str_a = mpz_serialize(user_array_out[i].ciphertext.x);
                str_b = mpz_serialize(user_array_out[i].ciphertext.y);
                do_Point_Addition(eid, str_a, str_b, i, 1);
        
		/*
		//Test

		printf("\n");

		for(int j = 8; j < 10; j++){

        		status = check_Setup1(eid, &len, 0, j);
        		status = check_Setup2(eid, &rv, buf_to_pass, len);
        		mpz_deserialize(&testingprint, buf_to_pass);
        		gmp_printf("Point is %Zd\n", testingprint);

        	}
		//End test
		*/
	}

	clock_t fault_end = clock();

	time_spent = (double)(fault_end - fault_begin) / CLOCKS_PER_SEC;
        printf("Fault Recovery Time: %f seconds\n", time_spent);

	int* sum = 0; 
	int temp = 0;
	uint32_t result_len = sizeof(sum);


	end = clock();

        time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
        printf("Total Aggregation Time: %f seconds\n", time_spent);


	//Compute final result of aggregation
        do_Aggregation_Result(eid, &sum, result_len);

	//printf("Sum: %i\n", sum);


	return 0;
}



