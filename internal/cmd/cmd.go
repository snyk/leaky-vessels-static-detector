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

package cmd

import (
	"fmt"
	"errors"
	
	"static-detector/internal/ast"
	"static-detector/internal/common"
	"static-detector/internal/analysis"
	"static-detector/internal/sources/gcr"
	"static-detector/internal/sources/daemon"
	"static-detector/internal/sources/dockerfile"
	"static-detector/internal/sources/dockerhub"
)

var log = common.GetLogger()

func AnalyzeImage(imageName string, imageSource string, opts common.Options) (int, []common.Result, error) {
	var da analysis.Analysis
	var code int
	var err error
	var res []common.Result

	switch(imageSource){
	case "daemon":
		da = &daemon.DaemonAnalyzer{ ImageName: imageName }
		code, res, err = analysis.RunInterface(da, opts)
	case "dockerhub":
		da = &dockerhub.DockerhubAnalyzer{ ImageName: imageName }
		code, res, err = analysis.RunInterface(da, opts)
	case "gcr":
		g := gcr.GCRAnalyzer{ ImageName: imageName }
		// Just pulls the image.
		err = g.Setup()
		if err != nil {
			code = 2
			break
		}
		da = &daemon.DaemonAnalyzer{ ImageName: imageName }
		code, res, err = analysis.RunInterface(da, opts)
	default:
		errMsg := fmt.Sprintf("Unsupported image source %s", imageSource)
		log.Error(errMsg)
		code = 2
		res = nil
		err = errors.New(errMsg)
	}

	return code, res, err
}

func AutoAnalyzeImage(imageName string, opts common.Options) (int, []common.Result, error) {
	var code int
	var err error
	var res []common.Result

	if gcr.IsGCRImage(imageName) {
		code, res, err = AnalyzeImage(imageName, "gcr", opts)
	} else if dockerhub.IsDockerhubImage(imageName) {
		code, res, err = AnalyzeImage(imageName, "dockerhub", opts)
	} else {
		code, res, err = AnalyzeImage(imageName, "daemon", opts)
	}

	if code > 1 || err != nil {
		log.Error("Base image analysis failed.")
		return 3, res, err
	}

	return code, res, err
}

func AnalyzeDockerfile(dockerfilePath string, opts common.Options) (int, []common.Result, error) {
	var da analysis.Analysis
	var code int
	var err error
	var res []common.Result

	df := dockerfile.DockerfileAnalyzer{ DockerfilePath: dockerfilePath }
	da = &df
	code, res, err = analysis.RunInterface(da, opts)
	if code == 2 {
		return code, nil, err
	}

	if opts.AnalyzeBaseImage {
		log.Debug("Running base image analysis.")
		data := df.GetDockerfileContents()
		baseImages, err := ast.GetBaseImages(data)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to extract base images from %s.", dockerfilePath)
			log.Error(errMsg)
			return 2, nil, errors.New(errMsg)
		}

		for _, base := range baseImages {
			code, baseRes, err := AutoAnalyzeImage(base, opts)
			if err != nil {
				errMsg := fmt.Sprintf("%s base image of %s auto-analysis failed.", base, dockerfilePath)
				log.Error(errMsg)
				return code, res, err
			}

			res = append(res, baseRes...)
		} 
	}

	return code, res, err
}
