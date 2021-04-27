#include "EnclaveGmpTest_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_tgmp_init(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	tgmp_init();
	return status;
}

static sgx_status_t SGX_CDECL sgx_do_Setup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_Setup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_do_Setup_t* ms = SGX_CAST(ms_do_Setup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	do_Setup(ms->ms_num);


	return status;
}

static sgx_status_t SGX_CDECL sgx_do_Point_Addition(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_Point_Addition_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_do_Point_Addition_t* ms = SGX_CAST(ms_do_Point_Addition_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_a = ms->ms_str_a;
	size_t _len_str_a = ms->ms_str_a_len ;
	char* _in_str_a = NULL;
	char* _tmp_str_b = ms->ms_str_b;
	size_t _len_str_b = ms->ms_str_b_len ;
	char* _in_str_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str_a, _len_str_a);
	CHECK_UNIQUE_POINTER(_tmp_str_b, _len_str_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str_a != NULL && _len_str_a != 0) {
		_in_str_a = (char*)malloc(_len_str_a);
		if (_in_str_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_a, _len_str_a, _tmp_str_a, _len_str_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_a[_len_str_a - 1] = '\0';
		if (_len_str_a != strlen(_in_str_a) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str_b != NULL && _len_str_b != 0) {
		_in_str_b = (char*)malloc(_len_str_b);
		if (_in_str_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_b, _len_str_b, _tmp_str_b, _len_str_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_b[_len_str_b - 1] = '\0';
		if (_len_str_b != strlen(_in_str_b) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	do_Point_Addition(_in_str_a, _in_str_b, ms->ms_id, ms->ms_fault);

err:
	if (_in_str_a) free(_in_str_a);
	if (_in_str_b) free(_in_str_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_do_Aggregation_Result(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_Aggregation_Result_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_do_Aggregation_Result_t* ms = SGX_CAST(ms_do_Aggregation_Result_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_sum = ms->ms_sum;
	uint32_t _tmp_len = ms->ms_len;
	size_t _len_sum = _tmp_len;
	int* _in_sum = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sum, _len_sum);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sum != NULL && _len_sum != 0) {
		if ( _len_sum % sizeof(*_tmp_sum) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sum = (int*)malloc(_len_sum)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sum, 0, _len_sum);
	}

	do_Aggregation_Result(_in_sum, _tmp_len);
	if (_in_sum) {
		if (memcpy_s(_tmp_sum, _len_sum, _in_sum, _len_sum)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sum) free(_in_sum);
	return status;
}

static sgx_status_t SGX_CDECL sgx_check_Setup1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_check_Setup1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_check_Setup1_t* ms = SGX_CAST(ms_check_Setup1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = check_Setup1(ms->ms_id, ms->ms_choice);


	return status;
}

static sgx_status_t SGX_CDECL sgx_check_Setup2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_check_Setup2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_check_Setup2_t* ms = SGX_CAST(ms_check_Setup2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_c = ms->ms_str_c;



	ms->ms_retval = check_Setup2(_tmp_str_c, ms->ms_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_e_mpz_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_mpz_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_mpz_add_t* ms = SGX_CAST(ms_e_mpz_add_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_a = ms->ms_str_a;
	size_t _len_str_a = ms->ms_str_a_len ;
	char* _in_str_a = NULL;
	char* _tmp_str_b = ms->ms_str_b;
	size_t _len_str_b = ms->ms_str_b_len ;
	char* _in_str_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str_a, _len_str_a);
	CHECK_UNIQUE_POINTER(_tmp_str_b, _len_str_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str_a != NULL && _len_str_a != 0) {
		_in_str_a = (char*)malloc(_len_str_a);
		if (_in_str_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_a, _len_str_a, _tmp_str_a, _len_str_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_a[_len_str_a - 1] = '\0';
		if (_len_str_a != strlen(_in_str_a) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str_b != NULL && _len_str_b != 0) {
		_in_str_b = (char*)malloc(_len_str_b);
		if (_in_str_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_b, _len_str_b, _tmp_str_b, _len_str_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_b[_len_str_b - 1] = '\0';
		if (_len_str_b != strlen(_in_str_b) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = e_mpz_add(_in_str_a, _in_str_b);

err:
	if (_in_str_a) free(_in_str_a);
	if (_in_str_b) free(_in_str_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_mpz_mul(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_mpz_mul_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_mpz_mul_t* ms = SGX_CAST(ms_e_mpz_mul_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_a = ms->ms_str_a;
	size_t _len_str_a = ms->ms_str_a_len ;
	char* _in_str_a = NULL;
	char* _tmp_str_b = ms->ms_str_b;
	size_t _len_str_b = ms->ms_str_b_len ;
	char* _in_str_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str_a, _len_str_a);
	CHECK_UNIQUE_POINTER(_tmp_str_b, _len_str_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str_a != NULL && _len_str_a != 0) {
		_in_str_a = (char*)malloc(_len_str_a);
		if (_in_str_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_a, _len_str_a, _tmp_str_a, _len_str_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_a[_len_str_a - 1] = '\0';
		if (_len_str_a != strlen(_in_str_a) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str_b != NULL && _len_str_b != 0) {
		_in_str_b = (char*)malloc(_len_str_b);
		if (_in_str_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_b, _len_str_b, _tmp_str_b, _len_str_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_b[_len_str_b - 1] = '\0';
		if (_len_str_b != strlen(_in_str_b) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = e_mpz_mul(_in_str_a, _in_str_b);

err:
	if (_in_str_a) free(_in_str_a);
	if (_in_str_b) free(_in_str_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_mpz_div(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_mpz_div_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_mpz_div_t* ms = SGX_CAST(ms_e_mpz_div_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_a = ms->ms_str_a;
	size_t _len_str_a = ms->ms_str_a_len ;
	char* _in_str_a = NULL;
	char* _tmp_str_b = ms->ms_str_b;
	size_t _len_str_b = ms->ms_str_b_len ;
	char* _in_str_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str_a, _len_str_a);
	CHECK_UNIQUE_POINTER(_tmp_str_b, _len_str_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str_a != NULL && _len_str_a != 0) {
		_in_str_a = (char*)malloc(_len_str_a);
		if (_in_str_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_a, _len_str_a, _tmp_str_a, _len_str_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_a[_len_str_a - 1] = '\0';
		if (_len_str_a != strlen(_in_str_a) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str_b != NULL && _len_str_b != 0) {
		_in_str_b = (char*)malloc(_len_str_b);
		if (_in_str_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_b, _len_str_b, _tmp_str_b, _len_str_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_b[_len_str_b - 1] = '\0';
		if (_len_str_b != strlen(_in_str_b) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = e_mpz_div(_in_str_a, _in_str_b);

err:
	if (_in_str_a) free(_in_str_a);
	if (_in_str_b) free(_in_str_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_mpf_div(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_mpf_div_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_mpf_div_t* ms = SGX_CAST(ms_e_mpf_div_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_a = ms->ms_str_a;
	size_t _len_str_a = ms->ms_str_a_len ;
	char* _in_str_a = NULL;
	char* _tmp_str_b = ms->ms_str_b;
	size_t _len_str_b = ms->ms_str_b_len ;
	char* _in_str_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str_a, _len_str_a);
	CHECK_UNIQUE_POINTER(_tmp_str_b, _len_str_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str_a != NULL && _len_str_a != 0) {
		_in_str_a = (char*)malloc(_len_str_a);
		if (_in_str_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_a, _len_str_a, _tmp_str_a, _len_str_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_a[_len_str_a - 1] = '\0';
		if (_len_str_a != strlen(_in_str_a) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str_b != NULL && _len_str_b != 0) {
		_in_str_b = (char*)malloc(_len_str_b);
		if (_in_str_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str_b, _len_str_b, _tmp_str_b, _len_str_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str_b[_len_str_b - 1] = '\0';
		if (_len_str_b != strlen(_in_str_b) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = e_mpf_div(_in_str_a, _in_str_b, ms->ms_digits);

err:
	if (_in_str_a) free(_in_str_a);
	if (_in_str_b) free(_in_str_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e_get_result(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_get_result_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_get_result_t* ms = SGX_CAST(ms_e_get_result_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str_c = ms->ms_str_c;



	ms->ms_retval = e_get_result(_tmp_str_c, ms->ms_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_e_pi(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e_pi_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e_pi_t* ms = SGX_CAST(ms_e_pi_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = e_pi(ms->ms_digits);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[12];
} g_ecall_table = {
	12,
	{
		{(void*)(uintptr_t)sgx_tgmp_init, 0, 0},
		{(void*)(uintptr_t)sgx_do_Setup, 0, 0},
		{(void*)(uintptr_t)sgx_do_Point_Addition, 0, 0},
		{(void*)(uintptr_t)sgx_do_Aggregation_Result, 0, 0},
		{(void*)(uintptr_t)sgx_check_Setup1, 0, 0},
		{(void*)(uintptr_t)sgx_check_Setup2, 0, 0},
		{(void*)(uintptr_t)sgx_e_mpz_add, 0, 0},
		{(void*)(uintptr_t)sgx_e_mpz_mul, 0, 0},
		{(void*)(uintptr_t)sgx_e_mpz_div, 0, 0},
		{(void*)(uintptr_t)sgx_e_mpf_div, 0, 0},
		{(void*)(uintptr_t)sgx_e_get_result, 0, 0},
		{(void*)(uintptr_t)sgx_e_pi, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


