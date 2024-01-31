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

package main

import (
	"os"
	"fmt"
	"flag"
	"strings"

	"github.com/joho/godotenv"

	"static-detector/internal/cmd"
	"static-detector/internal/common"
)

var (
	envFilePath string
	disable     string
	debug 		bool
	disableList []string

	imageSubcmd      = flag.NewFlagSet("image", flag.ExitOnError)
	dockerfileSubcmd = flag.NewFlagSet("dockerfile", flag.ExitOnError)

	log = common.GetLogger()
)

func setupCommonFlags() {
	for _, fs := range []*flag.FlagSet{imageSubcmd, dockerfileSubcmd} {
		fs.BoolVar(&debug, "debug", false, "Enable debug logs.")
		fs.StringVar(&envFilePath, "env", "", "Path to .env file.")
		fs.StringVar(&disable, "disable", "", 
			`Comma-seperated list of rule ids to turn off. List of rule Ids: 
1 - runc process.cwd & Leaked fds Container Breakout [CVE-2024-21626]
2 - Buildkit Mount Cache Race: Build-time Race Condition Container Breakout [CVE-2024-23651]
3 - Buildkit GRPC SecurityMode Privilege Check [CVE-2024-23653]
4 - Buildkit Build-time Container Teardown Arbitrary Delete [CVE-2024-23652]`)
	}
}

func setCommonFlags() { 
	if len(envFilePath) > 0 {
		err := godotenv.Load(envFilePath)
		if err != nil {
			log.Errorf("Error loading .env file: %v", err)
			os.Exit(2)
		}
	}

	if len(disable) > 0 {
		disableList = strings.Split(disable, ",")
	} else {
		disableList = []string{}
	}

	if debug {
		common.EnableDebug()
	}
}

func main() {
	setupCommonFlags()

	log.Info("Running Leaky Vessels Static Detector")

	// Image subcommand
	var imageName string

	imageSubcmd.StringVar(&imageName, "name", "", "Image name.")

	imageSubcmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", imageSubcmd.Name())
		imageSubcmd.PrintDefaults()
	}

	// Dockerfile subcommand
	var dockerfilePath string
	var analyzeBase bool

	dockerfileSubcmd.StringVar(&dockerfilePath, "f", "", "Path to dockerfile.")
	dockerfileSubcmd.BoolVar(&analyzeBase, "base", false, "Run analysis on base image.")

	dockerfileSubcmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", dockerfileSubcmd.Name())
		dockerfileSubcmd.PrintDefaults()
	}

	if len(os.Args) == 1 {
		errMsg := "No arguments provided."
		log.Error(errMsg)
		dockerfileSubcmd.Usage()
		imageSubcmd.Usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "image":
		imageSubcmd.Parse(os.Args[2:])
		if len(imageName) == 0 {
			log.Error("Empty image name.")
			os.Exit(2)
		}
	
		setCommonFlags()

		opts := common.Options{
			DisableRules: &disableList,
			AnalyzeBaseImage: false,
		}

		code, res, _ := cmd.AutoAnalyzeImage(imageName, opts)	
		common.PrintResults(res)
		os.Exit(code)

	case "dockerfile":
		dockerfileSubcmd.Parse(os.Args[2:])

		if len(dockerfilePath) == 0 {
			log.Error("Missing -f [DOCKERFILE_PATH]. See help for more details.")
			os.Exit(2)
		}

		setCommonFlags()

		opts := common.Options{
			DisableRules: &disableList,
			AnalyzeBaseImage: analyzeBase,
		}

		code, res, _ := cmd.AnalyzeDockerfile(dockerfilePath, opts)	
		common.PrintResults(res)
		os.Exit(code)
		
	default:
		errMSg := fmt.Sprintf("Unknown subcommand '%s'. Supported commands: image, dockerfile.", os.Args[1])
		log.Error(errMSg)
		dockerfileSubcmd.Usage()
		imageSubcmd.Usage()
		os.Exit(2)
	}
}
