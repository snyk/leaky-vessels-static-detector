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

package rules

import (
	"slices"
	"strconv"
	"strings"

	"static-detector/internal/common"

	"github.com/dlclark/regexp2"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

var log = common.GetLogger()

var RULES = []common.Rule{
	common.Rule{
		ID: 1,
		CVE: "CVE-2024-21626",
		Name: "runc process.cwd & Leaked fds Container Breakout",
		Blogpost: "https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout",
		Inst:        "WORKDIR",
		ArgRegex:    regexp2.MustCompile("/proc/self/fd", 0),
	},
	common.Rule{
		ID: 2,
		CVE: "CVE-2024-23651",
		Name: "Buildkit Mount Cache Race: Build-time Race Condition Container Breakout",
		Blogpost: "https://snyk.io/blog/cve-2024-23651-docker-buildkit-mount-cache-race",
		Inst:        "RUN",
		ArgRegex:    regexp2.MustCompile("--mount=type=cache", 0),
	},
	common.Rule{
		ID : 3,
		CVE: "CVE-2024-23653",
		Name: "Buildkit GRPC SecurityMode Privilege Check",
		Blogpost: "https://snyk.io/blog/cve-2024-23653-buildkit-grpc-securitymode-privilege-check",
		Inst:        "# syntax",
		ArgRegex:    regexp2.MustCompile(`# syntax= (?!(docker\.io/)?docker/dockerfile)`, 0),
	},
	common.Rule{
		ID : 4,
		CVE: "CVE-2024-23652",
		Name: "Buildkit Build-time Container Teardown Arbitrary Delete",
		Blogpost: "https://snyk.io/blog/cve-2024-23652-buildkit-build-time-container-arbitrary-delete",
		Inst:        "RUN",
		ArgRegex:    regexp2.MustCompile("--mount", 0),
	},
}

func isRuleDisabled(ruleId int, disableList []string) bool {
	if len(disableList) == 0 {
		return false
	}

	for _, v := range disableList {
		if strconv.Itoa(ruleId) == v {
			return true
		}
	}

	return false
}

func Run(ast *parser.Node, rules []common.Rule, srcName string, disableList *[]string) []common.Result {
	results := []common.Result{}
	nodes := ast.Children

	susInstructions := []string{}
	for _, rule := range rules {
		if !slices.Contains(susInstructions, rule.Inst) {
			susInstructions = append(susInstructions, rule.Inst)
		}
	}
	susInstructions = append(susInstructions, "ONBUILD")

	for _, node := range nodes {
		if !slices.Contains(susInstructions, node.Value) {
			continue
		}

		for _,rule := range rules {
			// Skip disabled rules.
			if isRuleDisabled(rule.ID, *disableList) {
				continue
			}

			testNodePart := node
			if strings.ToUpper(node.Value) == "ONBUILD" {
				testNodePart = node.Next.Children[0]
			}

			if rule.Inst == testNodePart.Value {
				args := strings.ReplaceAll(testNodePart.Original, testNodePart.Value + " ", "")
				if match, _ := rule.ArgRegex.MatchString(args); match {
					results = append(results, common.Result{
						CVE: rule.CVE,
						Name: rule.Name,
						Blogpost: rule.Blogpost,
						Source: srcName,
						Line: node.StartLine,
						Value: node.Original,
					})
				}
			}
		}
	}

	return results
}
