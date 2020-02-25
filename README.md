Secure function Evaluation - With Intel SGX
================================================


Introduction
------------
TODO

Documentation
-------------
- Follow this link to learn more about [Intel SGX](https://github.com/intel/linux-sgx)
- Learn more about the [secure function evaluation problem](https://crypto.stanford.edu/pbc/notes/crypto/sfe.html)


### Prerequisites:
- Support for Intel SGX hardware
  * or

- install Intel SDK for simulated enviroment.


Build  
-----------------------------------------
<<<<<<< HEAD
  * with Intel SGX HW	
  ```
    $ (cd enclave && make SGX_DEBUG=1 SGX_MODE=HW) && (cd bob && make SGX_DEBUG=1 SGX_MODE=HW) && (cd alice && make SGX_DEBUG=1 SGX_MODE=HW)
  ```
  * without Intel SGX HW	
  ```
    $ (cd enclave && make SGX_DEBUG=1) && (cd bob && make SGX_DEBUG=1) && (cd alice && make SGX_DEBUG=1)
  ```

Run  
-----------------------------------------
  ```
    $ ./alice/alice ../data/alice_data & ./bob/bob ../data/bob_data 
  ```
