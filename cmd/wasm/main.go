//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"syscall/js"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

var primitive tink.AEAD

func main() {
	fmt.Println("hello from the wasm")
	primitive = createKeySet()
	js.Global().Set("encryptData", js.FuncOf(encryptData))
	js.Global().Set("decryptData", js.FuncOf(decryptData))
	select {}
}

func encryptData(this js.Value, args []js.Value) interface{} {
	fmt.Println(args[0].String())
	encrypted := encrypt(primitive, args[0].String())
	b64Encrypted := base64.StdEncoding.EncodeToString(encrypted)
	return b64Encrypted
}

func decryptData(this js.Value, args []js.Value) interface{} {
	decodedData, err := base64.StdEncoding.DecodeString(args[0].String())
	if err != nil {
		panic(err)
	}
	decrypted := decrypt(primitive, decodedData)
	return string(decrypted)
}

func createKeySet() tink.AEAD {
	jsonKeyset := `{
		"key": [{
										"keyData": {
																		"keyMaterialType":
																										"SYMMETRIC",
																		"typeUrl":
																										"type.googleapis.com/google.crypto.tink.AesGcmKey",
																		"value":
																										"GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
										},
										"keyId": 294406504,
										"outputPrefixType": "TINK",
										"status": "ENABLED"
		}],
		"primaryKeyId": 294406504
}`
	keysetHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset)))
	if err != nil {
		log.Fatal(err)
	}
	primitive, err := aead.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	return primitive
}

func encrypt(primitive tink.AEAD, content string) []byte {
	associatedData := []byte("shh")
	encrypted, err := primitive.Encrypt([]byte(content), associatedData)
	if err != nil {
		panic(err)
	}

	return encrypted
}

func decrypt(primitive tink.AEAD, encryptedData []byte) []byte {
	associatedData := []byte("shh")
	result, err := primitive.Decrypt(encryptedData, associatedData)
	if err != nil {
		panic(err)
	}

	return result
}
