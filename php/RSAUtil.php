<?php

$passwordEncodeStr = rsaEncode("dahua2023","MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYf7WVvQijvtUGQ16QhMjc3E1Y2dyTqW5CP6Bq5jxRdlRpLeGbNmkygI3oOySBCsMwtLa2IsYBBU4B7zQxIzma++fredxHem0Yn4cVa7bCfhm4/aJIspmdiMY75v4uYZAsuoKJxX8AGy+Aixjol8NIkWceA5xHWneJeIydmTDHpQIDAQAB");
echo "����������ģ�\n".$passwordEncodeStr;
/**
 * RSA ����
 * @param unknown $password
 * @param unknown $rsa_public_key
 */
function rsaEncode($password,$rsa_public_key)
{
    // Ҫִ�еĴ���
    $rsa_public = "-----BEGIN PUBLIC KEY-----\n";
    $rsa_public = $rsa_public.$rsa_public_key;
    $rsa_public = $rsa_public."\n-----END PUBLIC KEY-----";
    $key = openssl_pkey_get_public($rsa_public);
    if (!$key) {
        echo "��Կ������\n";
        echo $rsa_public;
    }
    //openssl_public_encrypt ��һ������ֻ����string
    //openssl_public_encrypt �ڶ��������Ǵ���������
    //openssl_public_encrypt ������������openssl_pkey_get_public���ص���Դ����
    $return_en = openssl_public_encrypt($password, $crypted, $key);
    if (!$return_en) {
        echo "����ʧ��,����RSA��Կ";
    }
    return base64_encode($crypted);
}
?>