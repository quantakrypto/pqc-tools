<?php
// Legacy approach, migrated to KMS:
// $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
// openssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA256);
$kms = new KmsClient();
echo "keys are managed by KMS\n";
