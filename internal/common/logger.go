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
    "os"
	"runtime"

    "github.com/sirupsen/logrus"
)

const PREFIX = "[ + ] "

type CustomFormatter struct {
    logrus.Formatter
}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
    // Get the function name.
    if pc, _, _, ok := runtime.Caller(6); ok {
        if fn := runtime.FuncForPC(pc); fn != nil {
			entry.Message = PREFIX + entry.Message
        }
    }

    // Use the embedded formatter to format the entry.
    return f.Formatter.Format(entry)
}

func init(){
	Initialize()
}

// Initialize sets up the logger configuration.
func Initialize() {
    // Set the log output format to TextFormatter with color enabled.
    logrus.SetFormatter(&CustomFormatter{
        Formatter: &logrus.TextFormatter{
            FullTimestamp: true,
        },
    })

    // Output to stderr.
    logrus.SetOutput(os.Stderr)

    // Set the log level.
    logrus.SetLevel(logrus.InfoLevel)
}

// Get returns an instance of the logger.
func GetLogger() *logrus.Logger {
    return logrus.StandardLogger()
}

func EnableDebug() {
    logrus.SetLevel(logrus.DebugLevel)
}
