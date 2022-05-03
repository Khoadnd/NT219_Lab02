#!/bin/bash

avg_time() { 
    local -i n=$1
    local foo real sys user
    shift
    (($# > 0)) || return;
    { read foo real; read foo user; read foo sys ;} < <(
        { time -p for((;n--;)){ "$@" &>/dev/null ;} ;} 2>&1
    )
    printf "%.5f\n" $(
        bc -l <<<"$real/$n;" )
}

printf "avg_time ECB encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_1)
printf "avg_time ECB decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_1)

printf "avg_time CBC encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_2)
printf "avg_time CBC decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_2)

printf "avg_time OFB encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_3)
printf "avg_time OFB decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_3)

printf "avg_time CFB encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_4)
printf "avg_time CFB decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_4)

printf "avg_time CTR encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_5)
printf "avg_time CTR decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_5)

printf "avg_time XTS encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_6)
printf "avg_time XTS decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_6)

printf "avg_time CCM encryption: "
avg_time 10 $(../main < test_case_encryption/testcase_encryption_7)
printf "avg_time CCM decrypt: "
avg_time 10 $(../main < test_case_decryption/testcase_decryption_7)