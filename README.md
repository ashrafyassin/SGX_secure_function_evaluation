Secure function Evaluation - With Intel SGX
================================================


Introduction
------------
- This code aims to solve the secure function evaluation problem (see the Documentaion),for example users Alice and Bob each has his private input Xa and Xb respectively, and they wish to evaluate Fun(Xa,Xb) without revealing to the other side its private data.
- To do this we provided trusted execution environment for each user using Intel SGX enclaves.

Implementation  
------------
- For demonstration we used two applications, Alice and Bob respectively, each application has it's own enclave, that communicates with it's application using Ecalls and Ocalls, and for applications IPC we currently using files. 
- More detailed implementaion [pdf](https://github.com/ashrafyassin/SGX_secure_function_evaluation/blob/master/secure_function_evaluation-SGX.pdf)

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
    $ (cd enclave && make SGX_DEBUG=1 SGX_MODE=HW)
    $ (cd bob && make SGX_DEBUG=1 SGX_MODE=HW)
    $ (cd alice && make SGX_DEBUG=1 SGX_MODE=HW)
  ```
  * without Intel SGX Hardware - build in simulator-debug mode
  ```
    $ (cd enclave && make SGX_DEBUG=1)
    $ (cd bob && make SGX_DEBUG=1)
    $ (cd alice && make SGX_DEBUG=1)
  ```

Run  
-----------------------------------------
  ```
    $ ./alice/alice <ALICE_DATA_FILE> & ./bob/bob <BOB_DATA_FILE> 
  ```


testing 
-----------------------------------------
  ```
    $ (./alice/alice ../Tests/alice_data & ./bob/bob ../Tests/bob_data) > out
    $ (cd Tests && python test_generator.py)
    $ diff <(sort Tests/expected_out) <(sort out)
  ```

TODO
-------------
- currently applications exists on the same machine, we wish to be aple to run them on separte machines, to do this we need to change their IPC to sockets.
- For more secure protocol one should use local attestation, to asure the integrity of the other enclave, Or remote attestation if applications were in a separate machines.
