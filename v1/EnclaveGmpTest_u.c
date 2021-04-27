#include "EnclaveGmpTest_u.h"
#include <errno.h>

typedef struct ms_do_Setup_t {
	int ms_num;
} ms_do_Setup_t;

typedef struct ms_do_Point_Addition_t {
	char* ms_str_a;
	size_t ms_str_a_len;
	char* ms_str_b;
	size_t ms_str_b_len;
	int ms_id;
	int ms_fault;
} ms_do_Point_Addition_t;

typedef struct ms_do_Aggregation_Result_t {
	int* ms_sum;
	uint32_t ms_len;
} ms_do_Aggregation_Result_t;

typedef struct ms_check_Setup1_t {
	size_t ms_retval;
	int ms_id;
	int ms_choice;
} ms_check_Setup1_t;

typedef struct ms_check_Setup2_t {
	int ms_retval;
	char* ms_str_c;
	size_t ms_len;
} ms_check_Setup2_t;

typedef struct ms_e_mpz_add_t {
	size_t ms_retval;
	char* ms_str_a;
	size_t ms_str_a_len;
	char* ms_str_b;
	size_t ms_str_b_len;
} ms_e_mpz_add_t;

typedef struct ms_e_mpz_mul_t {
	size_t ms_retval;
	char* ms_str_a;
	size_t ms_str_a_len;
	char* ms_str_b;
	size_t ms_str_b_len;
} ms_e_mpz_mul_t;

typedef struct ms_e_mpz_div_t {
	size_t ms_retval;
	char* ms_str_a;
	size_t ms_str_a_len;
	char* ms_str_b;
	size_t ms_str_b_len;
} ms_e_mpz_div_t;

typedef struct ms_e_mpf_div_t {
	size_t ms_retval;
	char* ms_str_a;
	size_t ms_str_a_len;
	char* ms_str_b;
	size_t ms_str_b_len;
	int ms_digits;
} ms_e_mpf_div_t;

typedef struct ms_e_get_result_t {
	int ms_retval;
	char* ms_str_c;
	size_t ms_len;
} ms_e_get_result_t;

typedef struct ms_e_pi_t {
	size_t ms_retval;
	uint64_t ms_digits;
} ms_e_pi_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_EnclaveGmpTest = {
	0,
	{ NULL },
};
sgx_status_t tgmp_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveGmpTest, NULL);
	return status;
}

sgx_status_t do_Setup(sgx_enclave_id_t eid, int num)
{
	sgx_status_t status;
	ms_do_Setup_t ms;
	ms.ms_num = num;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveGmpTest, &ms);
	return status;
}

sgx_status_t do_Point_Addition(sgx_enclave_id_t eid, char* str_a, char* str_b, int id, int fault)
{
	sgx_status_t status;
	ms_do_Point_Addition_t ms;
	ms.ms_str_a = str_a;
	ms.ms_str_a_len = str_a ? strlen(str_a) + 1 : 0;
	ms.ms_str_b = str_b;
	ms.ms_str_b_len = str_b ? strlen(str_b) + 1 : 0;
	ms.ms_id = id;
	ms.ms_fault = fault;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveGmpTest, &ms);
	return status;
}

sgx_status_t do_Aggregation_Result(sgx_enclave_id_t eid, int* sum, uint32_t len)
{
	sgx_status_t status;
	ms_do_Aggregation_Result_t ms;
	ms.ms_sum = sum;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_EnclaveGmpTest, &ms);
	return status;
}

sgx_status_t check_Setup1(sgx_enclave_id_t eid, size_t* retval, int id, int choice)
{
	sgx_status_t status;
	ms_check_Setup1_t ms;
	ms.ms_id = id;
	ms.ms_choice = choice;
	status = sgx_ecall(eid, 4, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t check_Setup2(sgx_enclave_id_t eid, int* retval, char* str_c, size_t len)
{
	sgx_status_t status;
	ms_check_Setup2_t ms;
	ms.ms_str_c = str_c;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_mpz_add(sgx_enclave_id_t eid, size_t* retval, char* str_a, char* str_b)
{
	sgx_status_t status;
	ms_e_mpz_add_t ms;
	ms.ms_str_a = str_a;
	ms.ms_str_a_len = str_a ? strlen(str_a) + 1 : 0;
	ms.ms_str_b = str_b;
	ms.ms_str_b_len = str_b ? strlen(str_b) + 1 : 0;
	status = sgx_ecall(eid, 6, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_mpz_mul(sgx_enclave_id_t eid, size_t* retval, char* str_a, char* str_b)
{
	sgx_status_t status;
	ms_e_mpz_mul_t ms;
	ms.ms_str_a = str_a;
	ms.ms_str_a_len = str_a ? strlen(str_a) + 1 : 0;
	ms.ms_str_b = str_b;
	ms.ms_str_b_len = str_b ? strlen(str_b) + 1 : 0;
	status = sgx_ecall(eid, 7, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_mpz_div(sgx_enclave_id_t eid, size_t* retval, char* str_a, char* str_b)
{
	sgx_status_t status;
	ms_e_mpz_div_t ms;
	ms.ms_str_a = str_a;
	ms.ms_str_a_len = str_a ? strlen(str_a) + 1 : 0;
	ms.ms_str_b = str_b;
	ms.ms_str_b_len = str_b ? strlen(str_b) + 1 : 0;
	status = sgx_ecall(eid, 8, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_mpf_div(sgx_enclave_id_t eid, size_t* retval, char* str_a, char* str_b, int digits)
{
	sgx_status_t status;
	ms_e_mpf_div_t ms;
	ms.ms_str_a = str_a;
	ms.ms_str_a_len = str_a ? strlen(str_a) + 1 : 0;
	ms.ms_str_b = str_b;
	ms.ms_str_b_len = str_b ? strlen(str_b) + 1 : 0;
	ms.ms_digits = digits;
	status = sgx_ecall(eid, 9, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_get_result(sgx_enclave_id_t eid, int* retval, char* str_c, size_t len)
{
	sgx_status_t status;
	ms_e_get_result_t ms;
	ms.ms_str_c = str_c;
	ms.ms_len = len;
	status = sgx_ecall(eid, 10, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_pi(sgx_enclave_id_t eid, size_t* retval, uint64_t digits)
{
	sgx_status_t status;
	ms_e_pi_t ms;
	ms.ms_digits = digits;
	status = sgx_ecall(eid, 11, &ocall_table_EnclaveGmpTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

