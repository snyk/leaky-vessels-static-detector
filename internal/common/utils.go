/*
 * © 2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"io"
	"os"
	"fmt"
	"time"
	"bytes"
	"errors"
	"regexp"
	"net/http"
	"path/filepath"
	"encoding/json"
)

var log = GetLogger()

func ReadFile(path string) (string, error){
	absPath, _ := filepath.Abs(path)
	if _, err := os.Stat(absPath); err != nil {
		errMsg := fmt.Sprintf("File %s doesn't exist.", absPath)
		return "", errors.New(errMsg)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		errMsg := fmt.Sprintf(`Failed to read %s with err=%s`, path, err)
		log.Error(errMsg)
		return "", errors.New(errMsg)
	}

    return string(data), nil
}

func GetJson(url string, token string) (string, error){
	bodyReader := bytes.NewReader([]byte(""))
	req, err := http.NewRequest(http.MethodGet, url, bodyReader)
	if err != nil {
		   log.Fatal("client: could not create request: %s\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(token) > 0 {
		req.Header.Set("Authorization", "Bearer " + token)
	}
  
	client := http.Client{
	   Timeout: 30 * time.Second,
	}
  
	res, err := client.Do(req)
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Could not read response body: %s\n", err)
		log.Debug(errMsg)
		return "", errors.New(errMsg)
	}

	defer res.Body.Close()

	switch res.StatusCode{
	case 200:
		return string(resBody), nil
	default:	
		errMsg := fmt.Sprintf("Request to: %s returned: %d - %s", url, res.StatusCode, string(resBody))
		log.Debug(errMsg)
		return "", errors.New(errMsg)
	}
}

func PostJson(url string, body string, token string) (string, error) {
	bodyReader := bytes.NewReader([]byte(body))
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		   log.Fatal("client: could not create request: %s\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(token) > 0 {
		req.Header.Set("Authorization", "Bearer " + token)
	}
  
	client := http.Client{
	   Timeout: 30 * time.Second,
	}
  
	res, err := client.Do(req)
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Could not read response body: %s\n", err)
		log.Debug(errMsg)
		return "", errors.New(errMsg)
	}

	defer res.Body.Close()

	switch res.StatusCode{
	case 200:
		return string(resBody), nil
	default:	
		errMsg := fmt.Sprintf("Request to: %s returned: %d - %s", url, res.StatusCode, string(resBody))
		log.Debug(errMsg)
		return "", errors.New(errMsg)
	}
}

func PrintResults(result []Result){
	if len(result) == 0 {
		log.Info("No issues found.")
	} else {
		log.Info(fmt.Sprintf("Found %d issues.", len(result)))
	}


	if result != nil {
		if jsonRes, err := json.Marshal(result); len(jsonRes)>0 && err == nil{
			fmt.Println(string(jsonRes))
		}
	}
}

func ParseImageName(imageName string) (ImageName, error){
	res := ImageName{}
	if len(imageName) == 0 {
		errMsg := "Empty image name."
		log.Error(errMsg)
		return res, errors.New(errMsg)
	}
	re := regexp.MustCompile(`^([\w.\-\/]+)(?::([\w.\-]+))?(?:@([\w:]+))?$`)
	match := re.FindStringSubmatch(imageName)
	if match != nil {
		res.Name = match[1]
		res.Tag  = match[2]
		res.Hash = match[3]
	} else {
		errMsg := fmt.Sprintf("%s not a valid base image: [IMAGE]:[TAG]@[HASH]", imageName)
		log.Error(errMsg)
		return res, errors.New(errMsg)
	}

	if len(res.Name) == 0 {
		errMsg := fmt.Sprintf("Failed to extract image from %s", imageName)
		log.Error(errMsg)
		return res, errors.New(errMsg)
	}

	return res, nil
}