package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	accessKeyID     = ""
	secretAccessKey = ""
)

const (
	bucket = "test-dagm-bucket-listversioning"
	region = "us-east-1"
)

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func signRequest(accessKey, secretKey, region, bucket string) (host, raw string) {
	host = fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
	fmt.Println(host)
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	dateStamp := time.Now().UTC().Format("20060102")
	payloadHash := sha256Hex(nil)

	canonicalHeaders := fmt.Sprintf(
		"content-encoding:aws-chunked\nhost:%s\ntransfer-encoding:chunked\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		host, payloadHash, amzDate,
	)
	signedHeaders := "content-encoding;host;transfer-encoding;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		"PUT", "/", "versioning=",
		canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	)

	raw = fmt.Sprintf(
		"PUT /?versioning HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Encoding: aws-chunked\r\n"+
			"x-amz-content-sha256: %s\r\nx-amz-date: %s\r\nAuthorization: %s\r\n\r\n"+
			"0\r\n\r\n",
		host, payloadHash, amzDate, auth,
	)
	return host, raw
}

func main() {
	_, req := signRequest(accessKeyID, secretAccessKey, region, bucket)
	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{ServerName: host})
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req)); err != nil {
		panic(err)
	}

	fmt.Print("HERE")
	time.Sleep(3 * time.Second)

	//u := conn.NetConn()
	//t, _ := u.(*net.TCPConn)

	//_ = t.CloseWrite()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := io.ReadAll(conn)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(resp))
}
