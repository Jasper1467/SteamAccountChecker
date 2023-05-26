package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var timeoutCheck = 10
var timeoutLogin = 10

func main() {
	fmt.Println("Check timeout: ")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	inputTimeoutCheck := scanner.Text()

	// Convert the input string to an integer
	_timeoutCheck, err := strconv.Atoi(strings.TrimSpace(inputTimeoutCheck))
	if err != nil {
		fmt.Println("Invalid input. Please enter an integer.")
		return
	}

	timeoutCheck = _timeoutCheck

	fmt.Println("Login timeout: ")

	scanner.Scan()
	inputTimeoutLogin := scanner.Text()

	// Convert the input string to an integer
	_timeoutLogin, err := strconv.Atoi(strings.TrimSpace(inputTimeoutLogin))
	if err != nil {
		fmt.Println("Invalid input. Please enter an integer.")
		return
	}

	timeoutLogin = _timeoutLogin

	// Get the executable file's path
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Get the directory of the executable file
	dir := filepath.Dir(exePath)
	filePath := filepath.Join(dir, "login.txt")

	loginFile, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	defer func(loginFile *os.File) {
		err := loginFile.Close()
		if err != nil {
			fmt.Println("Error closing file:", err)
			return
		}
	}(loginFile)

	loginFileScanner := bufio.NewScanner(loginFile)

	var wg sync.WaitGroup
	results := make(chan error)

	for loginFileScanner.Scan() {
		var line = loginFileScanner.Text()
		parts := strings.Split(line, ":")

		username := parts[0]
		password := parts[1]

		wg.Add(1)
		go func(username, password string) {
			defer wg.Done()
			err := Login(username, password)
			results <- err
		}(username, password)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result != nil {
			fmt.Println("Login failed:", result)
		} else {
			fmt.Println("Login successful!")
		}
	}
}

// Login performs the login process for a Steam account.
func Login(username, password string) error {
	time.Sleep(time.Duration(timeoutCheck) * time.Second)

	headers := make(map[string]string)
	headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"

	rsaURL := fmt.Sprintf("https://steamcommunity.com/login/getrsakey?username=%s", username)
	var rsaRes, rsaErr = http.Get(rsaURL)
	if rsaErr != nil {
		return fmt.Errorf("failed to retrieve RSA key: %w", rsaErr)
	}
	defer rsaRes.Body.Close()

	rsaData, err := ioutil.ReadAll(rsaRes.Body)
	if err != nil {
		return fmt.Errorf("failed to read RSA response body: %w", err)
	}

	var rsaResponse struct {
		Success        bool   `json:"success"`
		PublicKeyMod   string `json:"publickey_mod"`
		PublicKeyExp   string `json:"publickey_exp"`
		Timestamp      string `json:"timestamp"`
		TokenGID       string `json:"token_gid"`
		SteamSessionID string `json:"steamid"`
	}
	if err := json.Unmarshal(rsaData, &rsaResponse); err != nil {
		return fmt.Errorf("failed to unmarshal RSA response: %w", err)
	}

	mod, _ := new(big.Int).SetString(rsaResponse.PublicKeyMod, 16)
	exp, _ := new(big.Int).SetString(rsaResponse.PublicKeyExp, 16)
	pubKey := rsa.PublicKey{N: mod, E: int(exp.Int64())}

	var passwordEncrypted, passEncErr = rsa.EncryptPKCS1v15(rand.Reader, &pubKey, []byte(password))
	if passEncErr != nil {
		return fmt.Errorf("failed to encrypt password with RSA key: %w", err)
	}

	loginURL := "https://steamcommunity.com/login/dologin/"
	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", base64.StdEncoding.EncodeToString(passwordEncrypted))
	formData.Set("rsatimestamp", rsaResponse.Timestamp)
	formData.Set("remember_login", "false")

	loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("User-Agent", headers["User-Agent"])

	client := &http.Client{Timeout: time.Duration(timeoutLogin) * time.Second}
	loginRes, err := client.Do(loginReq)
	if err != nil {
		return fmt.Errorf("failed to perform login request: %w", err)
	}
	defer loginRes.Body.Close()

	loginData, err := ioutil.ReadAll(loginRes.Body)
	if err != nil {
		return fmt.Errorf("failed to read login response body: %w", err)
	}

	print(loginData)

	fmt.Println(string(loginData))

	// Check the login response to determine success or failure
	// Modify the condition based on the actual response structure
	if strings.Contains(string(loginData), "login_complete") {
		return nil // Successful login
	}

	return fmt.Errorf("login failed")
}
