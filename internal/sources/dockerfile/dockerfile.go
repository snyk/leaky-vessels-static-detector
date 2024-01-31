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
 
 package dockerfile

import (
	"fmt"
	"errors"
	"strings"

	"static-detector/internal/ast"
	"static-detector/internal/rules"
	"static-detector/internal/common"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

var log = common.GetLogger()

type DockerfileAnalyzer struct{
	DockerfilePath string
	data string
}

func (d *DockerfileAnalyzer) Setup() (error) {
	data, err := common.ReadFile(d.DockerfilePath)
	if err != nil {
		errMsg := fmt.Sprintf("Failed reading path = %s", d.DockerfilePath)
		log.Error(errMsg)
		return err
	}

	d.data = data
	return nil
}

func (d *DockerfileAnalyzer) Analyze(opts common.Options) ([]common.Result, error) {
	tree, err := ast.Parse(d.data)
	if err != nil {
		errMsg := fmt.Sprintf("Parsing %s failed with err=%s",d.DockerfilePath, err)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}
	
	if !d.isValidDockerfile(tree.AST) {
		errMsg := "Invalid Dockerfile, please check contents."
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	rulesRes := rules.Run(tree.AST, rules.RULES, d.DockerfilePath, opts.DisableRules)
	return rulesRes, nil
}

func (d *DockerfileAnalyzer) isValidDockerfile(tree *parser.Node) bool {
	// Valid Dockerfile must include a FROM instruction or just a `# syntax`.
	for _, node := range(tree.Children) {
		if strings.ToLower(string(node.Value)) == "# syntax" {
			return true
		}

		if strings.ToUpper(string(node.Value)) == "FROM" {
			return true
		}
	}

	return false
}

func (d* DockerfileAnalyzer) GetDockerfileContents() string {
	return d.data
}