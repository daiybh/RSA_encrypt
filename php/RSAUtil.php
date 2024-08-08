<?php

$passwordEncodeStr = rsaEncode("dahua2023","MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYf7WVvQijvtUGQ16QhMjc3E1Y2dyTqW5CP6Bq5jxRdlRpLeGbNmkygI3oOySBCsMwtLa2IsYBBU4B7zQxIzma++fredxHem0Yn4cVa7bCfhm4/aJIspmdiMY75v4uYZAsuoKJxX8AGy+Aixjol8NIkWceA5xHWneJeIydmTDHpQIDAQAB");
echo "密码加密密文：\n".$passwordEncodeStr;
/**
 * RSA 加密
 * @param unknown $password
 * @param unknown $rsa_public_key
 */
function rsaEncode($password,$rsa_public_key)
{
    // 要执行的代码
    $rsa_public = "-----BEGIN PUBLIC KEY-----\n";
    $rsa_public = $rsa_public.$rsa_public_key;
    $rsa_public = $rsa_public."\n-----END PUBLIC KEY-----";
    $key = openssl_pkey_get_public($rsa_public);
    if (!$key) {
        echo "公钥不可用\n";
        echo $rsa_public;
    }
    //openssl_public_encrypt 第一个参数只能是string
    //openssl_public_encrypt 第二个参数是处理后的数据
    //openssl_public_encrypt 第三个参数是openssl_pkey_get_public返回的资源类型
    $return_en = openssl_public_encrypt($password, $crypted, $key);
    if (!$return_en) {
        echo "加密失败,请检查RSA秘钥";
    }
    return base64_encode($crypted);
}
?>