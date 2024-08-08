package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
	"encoding/base64"
	"strings"
	"errors"
    "fmt"
)

func main(){
    // RSA/ECB/PKCS1Padding
    // RSA是算法，ECB是分块模式，PKCS1Padding是填充模式

    // pkcs1私钥生成openssl genrsa -out pkcs1.pem 1024 
    // pkcs1转pkcs8私钥 ：openssl pkcs8 -in pkcs8.pem -nocrypt -out pkcs1.pem

    // pkcs1 BEGIN RSA PRIVATE KEY
    // pkcs8 BEGIN PRIVATE KEY
	
	txt := "dahua2023"
    publicKey := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVqywB5OgFALwfPu/uc3V4fSI+0Xy1yV3SxxYqH9Jgotjj6GbZ6ZXbXtF1cbDLQjbC0wfQQH+r5Xbr81y5N4afzqH8PMVbhPu1WlwvS1svFlsj/qwnnlaN3E0HicisoNLgi1AIv7wQVM9ZlYiDovShPZ57pfjX6bw2E1PmE2oaCwIDAQAB"
	var encrptTxt,error = RSAEncrypt(txt,publicKey)
	fmt.Println(error)
    fmt.Println(encrptTxt)

}

// RSAEncrypt 加密
func RSAEncrypt(origData string, publicKey string) (string, error) {
	publicKeyRAS := ""
	if !strings.Contains(publicKey, "----") {
		publicKeyRAS = "-----BEGIN RSA PUBLIC KEY-----\n" + publicKey + "\n-----END RSA PUBLIC KEY-----"
	}
	block, _ := pem.Decode([]byte(publicKeyRAS))
	if block == nil {
		return "", errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", errors.New("public key error")
	}
	pub := pubInterface.(*rsa.PublicKey)

	aimByte, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(origData))
	str := base64.StdEncoding.EncodeToString(aimByte)
	return str, nil
}