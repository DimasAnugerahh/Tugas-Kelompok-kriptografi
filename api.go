package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/blowfish"
)

var key = []byte("TugasKelompokKey")

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	ciphertext, err := encrypt(body, key)
	if err != nil {
		http.Error(w, "Error encrypting text", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(hex.EncodeToString(ciphertext)))
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	ciphertext, err := hex.DecodeString(string(body))
	if err != nil {
		http.Error(w, "Invalid ciphertext format", http.StatusBadRequest)
		return
	}

	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		http.Error(w, "Error decrypting text", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(plaintext))
}

func saveToFileHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	err = saveToFile(body)
	if err != nil {
		http.Error(w, "Error saving to file", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("File saved successfully"))
}

func saveToFile(data []byte) error {
	filename := "result.txt"

	if _, err := os.Stat(filename); err == nil {
		baseName := "result"
		ext := ".txt"
		counter := 1

		for {
			newFilename := fmt.Sprintf("%s_%d%s", baseName, counter, ext)
			if _, err := os.Stat(newFilename); os.IsNotExist(err) {
				filename = newFilename
				break
			}
			counter++
		}
	}

	return ioutil.WriteFile(filename, data, 0644)
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padSize := blowfish.BlockSize - (len(plaintext) % blowfish.BlockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	plaintext = append(plaintext, pad...)

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blowfish.BlockSize {
		cipher.Encrypt(ciphertext[i:i+blowfish.BlockSize], plaintext[i:i+blowfish.BlockSize])
	}

	return ciphertext, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blowfish.BlockSize {
		cipher.Decrypt(plaintext[i:i+blowfish.BlockSize], ciphertext[i:i+blowfish.BlockSize])
	}

	// Unpad
	padSize := int(plaintext[len(plaintext)-1])
	if padSize > 0 && padSize <= blowfish.BlockSize {
		plaintext = plaintext[:len(plaintext)-padSize]
	}

	return plaintext, nil
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/encrypt", encryptHandler).Methods("POST")
	r.HandleFunc("/decrypt", decryptHandler).Methods("POST")
	r.HandleFunc("/saveToFile", saveToFileHandler).Methods("POST")

	handler := cors.Default().Handler(r)

	fmt.Println("Server is running on :8080")
	http.ListenAndServe(":8080", handler)
}
