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

package ast

import (
	"bytes"
	"errors"
	"regexp"
	"slices"
	"strings"

	"static-detector/internal/common"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

var log = common.GetLogger()

func Parse(input string) (*parser.Result, error) {
	re := regexp.MustCompile("(?m)[\r\n]+^LABEL .*$")
	input = re.ReplaceAllString(input, "")

	tree, err := parseWithSyntax(input)
	if err != nil {
		return nil, err
	}

	return tree, nil
}

func parseWithSyntax(data string) (*parser.Result, error) {
	parsedWithSyntax, err := parser.Parse(bytes.NewBufferString(string(data)))
	if err != nil {
		if err.Error() == "file with no instructions" {
			// Create a mock result to populate with syntax if exists.
			parsedWithSyntax = &parser.Result{
				AST:         &parser.Node{},
				EscapeToken: '\\',
				Warnings:    []parser.Warning{},
			}
		} else {
			log.Error(err)
			return nil, err
		}
	}

	if _, cmdLine, _, _ := parser.DetectSyntax([]byte(data)); len(cmdLine) > 0 {
		// Insert syntax node into AST.
		parsedWithSyntax.AST.AddChild(&parser.Node{
			Value: "# syntax",
			Next: &parser.Node{
				Value:       cmdLine,
				Next:        nil,
				Children:    []*parser.Node{},
				Heredocs:    []parser.Heredoc{},
				Attributes:  map[string]bool{},
				Original:    "# syntax= " + cmdLine,
				Flags:       []string{},
				StartLine:   0,
				EndLine:     0,
				PrevComment: []string{},
			},
			Children:    []*parser.Node{},
			Heredocs:    []parser.Heredoc{},
			Attributes:  map[string]bool{},
			Original:    "# syntax= " + cmdLine,
			Flags:       []string{},
			StartLine:   0,
			EndLine:     0,
			PrevComment: []string{},
		}, 0, 0)

	}

	return parsedWithSyntax, nil
}

func ParseInstruction(node *parser.Node) string {
	if node.Next == nil {
		return node.Value
	} else {
		return strings.Join([]string{node.Value, parseFlags(node), ParseInstruction(node.Next), parseHeredocs(node)}, " ")
	}
}

func parseHeredocs(node *parser.Node) string {
	heredocs := ""
	for i := 0; i < len(node.Heredocs); i++ {
		heredocs += node.Heredocs[i].Content
	}

	return heredocs
}

func parseFlags(node *parser.Node) string {
	return strings.Join(node.Flags, " ")
}

func GetBaseImages(data string) ([]string, error) {
	baseNames := []string{}

	parsed, err := Parse(data)
	if err != nil {
		errMsg := "Failed to parse data."
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	aliases := map[string]string{}
	for _, node := range(parsed.AST.Children) {
        if strings.ToUpper(node.Value) == "FROM" {
			alias := ""
			name := ""
			for node.Next != nil{
				node = node.Next
				// Skip --platform.
				if strings.HasPrefix(node.Value, "--platform"){
					continue
				// Save alias.
				} else if strings.ToLower(node.Value) == "as" {
					alias = node.Next.Value
				// Save actual image name - comes before alias.	
				} else if len(alias) == 0 {
					name = node.Value
					baseNames = append( baseNames, name )
				// Save alias with actual image name value.
				} else {
					if _, ok := aliases[alias]; !ok && len(alias) > 0 {
						aliases[alias] = name
					}
				}
			}
		}
	}

	// Resolve aliases.
	resolvedNames := []string{}
	for _, base := range(baseNames){
		if val, ok := aliases[base]; ok {
			if !slices.Contains(resolvedNames, val){
				resolvedNames = append(resolvedNames, val)
			}
		} else {
			resolvedNames = append(resolvedNames, base)
		}
	}

	return resolvedNames, nil
}
