# Demo Program for the GNU\* Multiple Precision Arithmetic Library\* for Intel&reg; Software Guard Extensions

Note that this project is based off of the Intel SGX Port of GMP available at: https://github.com/intel/sgx-gmp-demo/blob/github/sgxgmpmath.c

This program demonstrates how to use the Intel SGX build of the GMP library. For more information about this project, see the accompanying article "[Building the GNU\* Multiple Precision\* Arithmetic Library for Intel® Software Guard Extensions](https://software.intel.com/en-us/articles/building-the-gnu-multiple-precision-library-for-intel-software-guard-extensions)".

## Prerequisites

To build and run the application, you'll need the following:

* The [GNU Multiple Precision Arithmetic Library for Intel Software Guard Extensions](https://github.com/intel/sgx-gmp)
  * both the Intel SGX and "stock" builds of this library are required
  * both builds can be produced from the above
* The [Intel SGX SDK](https://github.com/intel/linux-sgx)
* Intel SGX capable hardware

## Building

Configure the distribution by running the `configure` script. You'll need to specify the location of the standard and Intel SGX builds of GMP:

```
  --with-gmpdir=PATH           specify the libgmp directory
  --with-trusted-gmpdir=PATH   the trusted libgmp directory (default: gmp directory)
```

If both builds of the library are installed to the same directory, you can just specify `--with-gmpdir=PATH`.

To compile the applications, run `make`.

## Running the Demo Programs

### sgxgmpmath

This project was tested on Ubuntu 18.04 LTS and depends on the following:

GNU GMP (https://gmplib.org/), Intel SGX (https://github.com/intel/linux-sgx), and Intel's port of GNU GMP for SGX (https://github.com/intel/sgx-gmp).

After installing the dependencies, simply type 'make' to build in the v1 or v2 directories.

Specify users and faults using macros.
