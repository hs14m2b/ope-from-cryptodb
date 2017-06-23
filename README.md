# Shuffled Frequency-Hiding Encryption based on OPE from CryptDB

This is an implementation of the Shuffled Frequency-Hiding Encryption scheme developed as part of my MSc in Health Informatics Project. The Order-preserving encryption (OPE) lib underpinning the scheme is forked from hilder-victor/ope-from-cryptodb which in turn was extracted from the CryptoDB (http://css.csail.mit.edu/cryptdb/).

The Makefile has been modified to run on Centos 6.4, and required the installation of devtoolset-2 to upgrade the g++ compiler to version 4.8

It is necessary to compile the ```encryptionUtils``` project first and generate the JNI headers. The header file has been pre-generated for convenience and is needed in the same folder as the cpp source to successfully compile.

Take a look to ```encrypt.cpp```, ```decrypt.cpp``` and to ```Makefile``` to see how to use and compile this project.

The project could benefit from re-factoring to remove the code duplication between the JNI implementation and the stand-alone executables - the challenge to achieve this was beyond my c++ skills (having first learned c back in 1997, and thereafter never used it again) and wasn't needed for the purposes of my masters project!
