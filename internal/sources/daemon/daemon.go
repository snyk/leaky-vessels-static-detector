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

package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"static-detector/internal/ast"
	"static-detector/internal/common"
	"static-detector/internal/rules"
)

var log = common.GetLogger()

type DaemonAnalyzer struct{
	ImageName string
	data string
}

func (d *DaemonAnalyzer) Setup() (error) {
	d.data = ""
	
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
    if err != nil {
        errMSg := "Failed to get image list from local daemon."
		log.Error(errMSg)
		return errors.New(errMSg)
    }
	
	isLocal := false
    for _, image := range images {
		for _, name := range image.RepoTags{
			if strings.HasPrefix(name, d.ImageName) {
				isLocal = true
				break
			}
		}
    }

	if !isLocal {
		dbgMsg := fmt.Sprintf("Image not found locally, downloading it now from %s", d.ImageName)
		log.Debug(dbgMsg)
		reader, err := cli.ImagePull(context.Background(), d.ImageName, types.ImagePullOptions{})
		if err != nil {
			errMsg := fmt.Sprintf("Failed to pull image %s: %v", d.ImageName, err)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		defer reader.Close()
	}

	dbgMsg := fmt.Sprintf("Getting docker image layer history for %s", d.ImageName)
	log.Debug(dbgMsg)

	history, err := cli.ImageHistory(context.Background(), d.ImageName)
	if err != nil {
		errMsg := fmt.Sprintf("Failed getting image history for %s", d.ImageName)
		log.Error(errMsg)
		return errors.New(errMsg)
	}

	if len(history) == 0 {
		errMsg := fmt.Sprintf("Got empty image history for %s", d.ImageName)
		log.Error(errMsg)
		return errors.New(errMsg)
	}

	for _, histElem := range history {
		d.data += histElem.CreatedBy + "\n"
	}

	dbgMsg = fmt.Sprintf("Getting image inspect data for %s", d.ImageName)
	log.Debug(dbgMsg)
	inspect, _, err := cli.ImageInspectWithRaw(context.Background(), d.ImageName)
	if err != nil {
		errMsg := fmt.Sprintf("Failed image inspect for %s", d.ImageName)
		log.Error(errMsg)
		return errors.New(errMsg)
	}

	for _, inst := range inspect.Config.OnBuild {
		d.data += fmt.Sprintf("ONBUILD %s\n", inst) 
	}

	return nil
}

func (d *DaemonAnalyzer) Analyze(opts common.Options) ([]common.Result, error) {
	tree, err := ast.Parse(d.data)
	if err != nil {
		errMsg := fmt.Sprintf("Parsing %s failed with err=%s", d.ImageName, err)
		log.Error(errMsg)
		return nil, err
	}

	rulesRes := rules.Run(tree.AST, rules.RULES, "daemon://" + d.ImageName, opts.DisableRules)	
	return rulesRes, nil
}

func InspectImage(imageName string) (*types.ImageInspect, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	inspect, _, _ := cli.ImageInspectWithRaw(context.Background(), imageName)
	log.Debug(inspect)
	return &inspect, nil
}
