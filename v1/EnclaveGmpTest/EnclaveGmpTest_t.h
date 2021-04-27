#ifndef ENCLAVEGMPTEST_T_H__
#define ENCLAVEGMPTEST_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tgmp.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void tgmp_init(void);
void do_Setup(int num);
void do_Point_Addition(char* str_a, char* str_b, int id, int fault);
void do_Aggregation_Result(int* sum, uint32_t len);
size_t check_Setup1(int id, int choice);
int check_Setup2(char* str_c, size_t len);
size_t e_mpz_add(char* str_a, char* str_b);
size_t e_mpz_mul(char* str_a, char* str_b);
size_t e_mpz_div(char* str_a, char* str_b);
size_t e_mpf_div(char* str_a, char* str_b, int digits);
int e_get_result(char* str_c, size_t len);
size_t e_pi(uint64_t digits);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
