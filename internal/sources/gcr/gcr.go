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

package gcr

import (
	"os"
	"fmt"
	"bufio"
	"errors"
    "regexp"
	"context"
	"encoding/base64"
	"encoding/json"

	"golang.org/x/sync/errgroup"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"

	"static-detector/internal/common"
)

var log = common.GetLogger()

type GCRAnalyzer struct {
    ImageName string
}

// Setup() pulls an image.
func (g *GCRAnalyzer) Setup() error {
    if !IsGCRImage(g.ImageName) {
        errMsg := fmt.Sprintf("%s is not a GCR image name.", g.ImageName)
        log.Error(errMsg)
        return errors.New(errMsg)
    }

    serviceAccountJSON := os.Getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if serviceAccountJSON == "" {
        errMsg := "GOOGLE_SERVICE_ACCOUNT_JSON is not set."
		log.Error(errMsg)
		return errors.New(errMsg)
    }

    // Create a Docker client.
    cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
    if err != nil {
        errMsg := "Failed to create a Docker client."
		log.Error(errMsg)
		return errors.New(errMsg)    
	}

    // Authentication configuration.
    authConfig := registry.AuthConfig{
        ServerAddress: "https://gcr.io",
        Username:      "_json_key",
        Password:      serviceAccountJSON,
    }

    encodedJSON, err := json.Marshal(authConfig)
    if err != nil {
        errMsg := "Failed to JSON encode GCR credentials."
		log.Error(errMsg)
		return errors.New(errMsg)    
    }
    authStr := base64.URLEncoding.EncodeToString(encodedJSON)

    var eg errgroup.Group
	
    eg.Go(func() error { 
        out, err := cli.ImagePull(context.Background(), g.ImageName, types.ImagePullOptions{RegistryAuth: authStr})
        if err != nil {
            log.Error(err)
            return err
        }
        defer out.Close()
        
        scanner := bufio.NewScanner(out)
        for scanner.Scan() {
            log.Debug(scanner.Text())
        }
        
        return nil
    })

	if err := eg.Wait(); err != nil {
        errMsg := fmt.Sprintf("Failed to pull %s: %s.", g.ImageName, err)
		log.Error(errMsg)
		return errors.New(errMsg)    
	}

	return nil
}

// Empty method - analysis is done by DaemonAnalyzer once images is pulled. 
func (d *GCRAnalyzer) Analyze(opts common.Options) ([]common.Result, error) {
    return nil, nil
}

func IsGCRImage(imageName string) bool {
    // Check Container Registry image names.
    re := regexp.MustCompile(`^(?:([\w\.]+))?gcr\.io`)
    match := re.FindStringSubmatch(imageName)
    if match != nil {
        return true
    }

    return false
}
