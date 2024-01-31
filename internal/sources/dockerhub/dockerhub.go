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

package dockerhub

import (
	"os"
	"fmt"
	"regexp"
	"errors"
	"net/url"
	"strings"
	"encoding/json"

	"golang.org/x/sync/errgroup"

	"static-detector/internal/ast"
	"static-detector/internal/common"
	"static-detector/internal/rules"
)

const DOCKERHUB_API_URL string = "https://hub.docker.com/v2"
const IMAGES_PATH string = "/repositories/%s/tags/%s/images?page_size=100"
const TAGS_PATH string = "/repositories/%s/%s/tags?page_size=100"
const LOGIN_PATH string = "/users/login"
const IMAGE_TAG_PATH string = "/repositories/%s/%s/tags/%s"

var CONTAINER_REG_RE = regexp.MustCompile(`(gcr\.io|dkr\.ecr|mcr\.microsoft\.com|ghcr\.io|registry\.gitlab\.com|quay\.io|icr\.io|ocir\.io|registry\.aliyuncs\.com)`)

var log = common.GetLogger()

type DockerhubAnalyzer struct {
	ImageName string
	token string
}

func IsDockerhubImage(imageName string) bool {
	parsedName, err := common.ParseImageName(imageName)
	if err != nil {
		log.Error("Failed to parse image name.")
		return false
	}

	// if not [repo]/[name] -> library image.
	if !strings.Contains(parsedName.Name, "/") {
		parsedName.Name = "library/" + parsedName.Name
	}

	re := regexp.MustCompile(`(?:([\w\.\-]+)/)?(?:([\w/]+))`)
	match := re.FindStringSubmatch(parsedName.Name)
	if match == nil {
		errMsg := fmt.Sprintf("Failed to extract namespace and repo from %s", parsedName.Name)
		log.Error(errMsg)
		return false
	}

	namespace := match[1]
	repo := match[2]

	url := DOCKERHUB_API_URL + fmt.Sprintf(IMAGE_TAG_PATH, namespace, repo, parsedName.Tag)
	token, err := GetAuthToken(os.Getenv("DH_USERNAME"), os.Getenv("DH_PASSWORD_OR_PAT"))
	if err != nil {
		errMSg := "Failed getting auth token."
		log.Error(errMSg)
		return false
	}
	_, err = common.GetJson(url, token)
	if err != nil {
		return false
	} else {
		return true
	}
}

func GetAuthToken(username string, password string) (string, error) {
	if len(username) == 0 || len(password) == 0 {
		errMSg := "Empty credentials. Please provide via DH_USERNAME / DH_PASSWORD_OR_PAT env vars."
		log.Error(errMSg)
		return "", errors.New(errMSg)
	}

	jsonBody := fmt.Sprintf(`{"username":"%s", "password":"%s"}`, username, password)
	loginURL, _ := url.JoinPath(DOCKERHUB_API_URL, LOGIN_PATH)
	res, err := common.PostJson(loginURL, jsonBody, "")
	if err != nil {
		return "", err
	}

	var resJson map[string]interface{}
	json.Unmarshal([]byte(res), &resJson)
	return resJson["token"].(string), nil
}


func (d* DockerhubAnalyzer) Setup() (error) {
	token, err := GetAuthToken(os.Getenv("DH_USERNAME"), os.Getenv("DH_PASSWORD_OR_PAT"))
	if err != nil {
		errMsg := "Dockerhub analyzer setup failed."
		log.Error(errMsg)
		return nil
	}
	d.token = token
	return nil
}

func (d *DockerhubAnalyzer) Analyze(opts common.Options) ([]common.Result, error) {
	parsedName, _ := common.ParseImageName(d.ImageName)

	// if not [repo]/[name] -> library image.
	if !strings.Contains(parsedName.Name, "/") {
		parsedName.Name = "library/" + parsedName.Name
	}

	re := regexp.MustCompile(`(?:([\w\.\-]+)/)?(?:([\w/]+))`)
	match := re.FindStringSubmatch(parsedName.Name)
	if match == nil {
		errMsg := fmt.Sprintf("Failed to extract namespace and repo from %s", parsedName.Name)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	namespace := match[1]
	repo := match[2]

	var tags []string
	if len(parsedName.Tag) > 0 {
		tags = []string{parsedName.Tag}
	} else if len(parsedName.Tag) == 0 {
		tags = []string{"latest"}
	} else {
		var err error
		tags, err = d.getImageTags(namespace, repo)
		if err != nil {
 			errMsg := fmt.Sprintf("Failed to get %s tags", d.ImageName)
			log.Error(errMsg)
			return nil, errors.New(errMsg)
		}
	}

	tagsRes := []common.Result{}

	var eg errgroup.Group
	layers := make(chan map[string]string, len(tags))
	
	for _, t := range tags {
		tag := t
		eg.Go(func() error { 
			return d.getImageLayers(parsedName.Name, tag, layers)
		})
	}

	if err := eg.Wait(); err != nil {
		errMsg := fmt.Sprintf("Failed to get image layers for %s", d.ImageName)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}
	
	close(layers)

	for l := range layers {
		paresdDockerhubImageLayers, err := ast.Parse(l["layers"])
		if err != nil {
			errMsg := fmt.Sprintf(`Failed to parse Dockerhub image layers for %s`, d.ImageName)
			log.Error(errMsg)
			return nil, err
		}	

		dockerhubRes := rules.Run(paresdDockerhubImageLayers.AST, rules.RULES, "dockerhub://" + d.ImageName + ":" + l["tag"], opts.DisableRules)
		tagsRes = append(tagsRes, dockerhubRes...)
	}

	return tagsRes, nil
}

func (d * DockerhubAnalyzer) isContainerRegistry(imageName string) bool {
	if match := CONTAINER_REG_RE.FindString(imageName); len(match) > 0 {
		return true
	} else {
		return false
	}
}

func (d * DockerhubAnalyzer) getImageTags(namespace string, repo string) ([]string, error) {
	url := DOCKERHUB_API_URL + fmt.Sprintf(TAGS_PATH, namespace, repo)
	next := url
	tags := []string{}
	for len(next) > 0 {
		res, err := common.GetJson(next, d.token)
		if err != nil {
			log.Error("Failed fetching tags.")
			return nil, err
		}

		var resJson map[string]interface{}
		if err := json.Unmarshal([]byte(res), &resJson); err == nil {
			if len(resJson) > 0 {
				if resJson["next"] != nil {
					next = resJson["next"].(string)
				} else {
					next = ""
				}
				results := resJson["results"].([]interface{})
				for _, r := range results {
					mapRes := r.(map[string]interface{})
					tags = append(tags, mapRes["name"].(string))
				}
			}
		} else {
			log.Error("Failed to unmarshal %v", resJson)
			return nil, err
		}
	}
	return tags, nil
}

func (d * DockerhubAnalyzer) getImageLayers(imageName string, imageTag string, results chan<- map[string]string) error {
	if d.isContainerRegistry(imageName) {
		log.Debug(fmt.Sprintf("%s is not hosted on Dockerhub, returning.", imageName))
		results <- map[string]string{}
		return nil
	}

	dbgMsg := fmt.Sprintf("Getting image layers for %s:%s", imageName, imageTag)
	log.Debug(dbgMsg)

	layers := ""
	Url := DOCKERHUB_API_URL  + fmt.Sprintf(IMAGES_PATH, imageName, imageTag)
	res, err := common.GetJson(Url, d.token)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			errMsg := fmt.Sprintf("%s not found on Dockerhub, might be a local image (try running with `--daemon`)", imageName)
			log.Error(errMsg)
		} else {
			errMsg := fmt.Sprintf("Failed to get %s image layers", imageName)
			log.Error(errMsg)
		}
		results <- map[string]string{}
		return err
	}

	var resJson []map[string]interface{}
	if err := json.Unmarshal([]byte(res), &resJson); err == nil {
		if len(resJson) > 0 {
			// TBD - return first arch + os - change!!!
			if resJson[0]["layers"] != nil {
				imageLayers := resJson[0]["layers"].([]interface{})
				for _, val := range imageLayers {
					layers += val.(map[string]interface{})["instruction"].(string) + "\n"
				}
			} else {
				dbgMsg := fmt.Sprintf("Got empty image layers for %s:%s", imageName, imageTag)
				log.Debug(dbgMsg)
			}
		}
	} else {
		log.Error("Failed to unmarshal %v", resJson)
		results <- map[string]string{}
		return err
	}

	results <- map[string]string{"tag": imageTag, "layers": layers}
	return nil
}
