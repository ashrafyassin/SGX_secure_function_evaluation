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
<<<<<<< HEAD
- install Intel SDK for simulated enviroment.
=======
-install Intel SDK for simulated enviroment.
>>>>>>> 7c35399333ddb97ebb1bf001491701a8a614ee79


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
=======
  ```
    $ (cd enclave && make SGX_DEBUG=1 SGX_MODE=HW ) && (cd bob && make SGX_DEBUG=1 SGX_MODE=HW) && (cd alice && make SGX_DEBUG=1 SGX_MODE=HW)
>>>>>>> 7c35399333ddb97ebb1bf001491701a8a614ee79
  ```

Run  
-----------------------------------------
  ```
    $ ./alice/alice ../data/alice_data & ./bob/bob ../data/bob_data 
  ```
