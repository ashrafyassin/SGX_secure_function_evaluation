Secure function Evaluation - With Intel SGX
================================================


Introduction
------------
TODO

Documentation
-------------
- See [Developer Reference](https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf) for more about Intel SGX SDK
- Learn more about the [secure function evaluation problem](https://crypto.stanford.edu/pbc/notes/crypto/sfe.html)


### Prerequisites:
- [Intel(R) Software Guard Extensions for Linux* OS](https://github.com/intel/linux-sgx) is needed
- working with eclipse requires SGX eclipse [plugin](https://github.com/intel/linux-sgx/tree/master/Linux_SGXEclipsePlugin)


Build  
-----------------------------------------
  * with Intel SGX Hardware	- build in hardware-debug mode
  ```
    $ (cd enclave && make SGX_DEBUG=1 SGX_MODE=HW) && (cd bob && make SGX_DEBUG=1 SGX_MODE=HW) && (cd alice && make SGX_DEBUG=1 SGX_MODE=HW)
  ```
  * without Intel SGX Hardware - build in simulator-debug mode
  ```
    $ (cd enclave && make SGX_DEBUG=1) && (cd bob && make SGX_DEBUG=1) && (cd alice && make SGX_DEBUG=1)
  ```

Run  
-----------------------------------------
  ```
    $ ./alice/alice <ALICE_DATA_FILE> & ./bob/bob <BOB_DATA_FILE> 
  ```
