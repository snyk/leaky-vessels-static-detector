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
 
package analysis

import (
	"fmt"
	"errors"
	"reflect"
	"runtime"

	"static-detector/internal/common"
)

type Analyze func(opts common.Options) ([]common.Result, error)
type Setup func() (error)

type Analysis interface {
	Setup() (error)	
	Analyze(opts common.Options) ([]common.Result, error)
}

var log = common.GetLogger()

func RunSetupAnalyze(setup Setup, analyze Analyze, opts common.Options) (int, []common.Result, error) {
	err := setup()
	if err != nil {
		errMsg := fmt.Sprintf("Failed %s setup, aborting.", runtime.FuncForPC(reflect.ValueOf(setup).Pointer()).Name())
		log.Error(errMsg)
		return 2, nil, errors.New(errMsg)
	}

	res, err := analyze(opts)
	if err == nil{
		if len(res) == 0 {
			return 0, res, nil
		} else {
			return 1, res, nil
		}
	} else {
		return 2, res, err
	}	
}

func RunInterface(a Analysis, opts common.Options) (int, []common.Result, error){
	err := a.Setup()
	if err != nil {
		errMsg := fmt.Sprintf("Failed %s=%s setup, aborting.", reflect.TypeOf(a), reflect.ValueOf(a))
		log.Error(errMsg)
		return 2, nil, errors.New(errMsg)
	}

	res, err := a.Analyze(opts)
	if err == nil{
		if len(res) == 0 {
			return 0, res, nil
		} else {
			return 1, res, nil
		}
	} else {
		return 2, res, err
	}	
}