// @ts-check

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

import isGlob from "is-glob";
import { getListOfFilesToDownload, downloadFile } from "./helper.js";

/** @type boolean */
// let hasRepoScope;

/**
 * An Octoherd script to download files from repositories
 *
 * @param {import('@octoherd/cli').Octokit} octokit
 * @param {import('@octoherd/cli').Repository} repository
 * @param {object} options
 * @param {boolean} [options.ignoreArchived] Ignores archive repositories
 * @param {boolean} [options.ignoreForks] Ignores forks repositories
 * @param {boolean} [options.ignorePublic] Ignores public repositories
 * @param {boolean} [options.ignorePrivate] Ignores private repositories
 * @param {string} options.source Path to the destination directory
 * @param {string} options.output File path to download. Note: Directories are not supported yet
 */
export async function script(
  octokit,
  repository,
  {
    source,
    output = process.cwd(),
    ignoreArchived = true,
    ignoreForks = false,
    ignorePublic = false,
    ignorePrivate = false,
  },
) {
  // if (!hasRepoScope) {
  //   const { headers } = await octokit.request("HEAD /");
  //   const scopes = new Set(headers["x-oauth-scopes"].split(", "));

  //   if (!scopes.has("repo")) {
  //     throw new Error(
  //       `The "repo" scope is required for this script. Create a token at https://github.com/settings/tokens/new?scopes=repo then run the script with "-T <paste token here>"`
  //     );
  //   }
  //   hasRepoScope = true;
  // }

  if (ignoreArchived && repository.archived) {
    octokit.log.warn(`IGNORE repository is archived`);
    return;
  }

  if (ignoreForks && repository.fork) {
    octokit.log.warn(`IGNORE repository is a fork`);
    return;
  }

  if (ignorePublic && !repository.private) {
    octokit.log.warn(`IGNORE repository is public`);
    return;
  }

  if (ignorePrivate && repository.private) {
    octokit.log.warn(`IGNORE repository is private`);
    return;
  }

  if (!source) {
    octokit.log.error(
      "Please specify a source file to download with --source=README.md",
    );
    process.exit(1);
  }

  if (!output) {
    octokit.log.error(
      "Please specify a source file to download with --source=README.md --output=./out",
    );
    process.exit(1);
  }

  let filesToDownload = [source];

  if (isGlob(source)) {
    filesToDownload = await getListOfFilesToDownload(
      octokit,
      repository,
      source,
    );
  }

  // for repos with a large  number of files, oktokit sometimes fails. always request the non glob files
  filesToDownload = filesToDownload.concat(source.split(/[,{}]+/));
  filesToDownload = Array.from(
    new Set(
      filesToDownload.filter(
        (item) => item.length > 0 && item.indexOf("*") < 0,
      ),
    ),
  );

  if (filesToDownload.length > 1) {
    octokit.log.debug(`Start downloading ${filesToDownload.length} files`);
  }

  if (filesToDownload.length === 0) {
    octokit.log.warn(`No matches found for ${source}.`);
  }

  for (const item of filesToDownload) {
    // deepcode ignore PT: expected behavior
    await downloadFile(octokit, repository, output, item);
  }
}
