#!/bin/bash

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0

vault write ssh/creds/root_otp ip=127.0.0.1
vault ssh -role root_otp -mode otp root@127.0.0.1
OTP Password