import Papa from "papaparse";
import { fetchFileContent } from "./fileUtils.js";
import { detectSensitiveDataTxt, detectSensitiveDataCsv, detectSensitiveDataForPR } from "./securityPatterns.js";

export function getModifiedFiles(payload) {
  // Exclude the configuration file from the list of modified files
  const configFile = "configuration-sensitibot.txt";
  return payload.commits
    .flatMap(commit => commit.added.concat(commit.modified))
    .filter(file => !file.endsWith(configFile));
}

export async function analyzeTxtFiles(context, payload, files, patterns, exclusions) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.txt')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const detected = detectSensitiveDataTxt(fileContent, patterns, exclusions);
        for (const { label, matches } of detected) {
          vulnerabilities.push({ file, label, matches });
        }
      }
    }
  }
  return vulnerabilities;
}

export async function analyzeCsvFiles(context, payload, files, patterns, exclusions) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.csv')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const detected = detectSensitiveDataCsv(fileContent, patterns, exclusions);
        for (const { label, matches } of detected) {
          vulnerabilities.push({ file, label, matches });
        }
      }
    }
  }
  return vulnerabilities;
}

export async function createIssue(context, vulnerabilities) {
  const body = vulnerabilities
    .map(vuln => `**${vuln.file}** Contains (${vuln.label}): ${vuln.matches.join(', ')}`)
    .join('\n');
  const issue = context.issue({
    title: 'Sensitive information found',
    body
  });

  try {
    context.log.info('Creating issue with body:', body);
    await context.octokit.issues.create(issue);
    context.log.info('Issue created successfully');
  } catch (error) {
    context.log.error('Error creating issue:', error);
  }
}

export async function createPullRequestToRemoveSensitiveData(context, payload, patterns, exclusions) {
  const branchName = `remove-sensitive-data-${Date.now()}`;
  const baseBranch = payload.repository.default_branch;
  const modifiedFiles = getModifiedFiles(payload);
  const txtFiles = modifiedFiles.filter(file => file.endsWith('.txt'));

  const vulnerabilities = {};
  const changes = [];

  for (const file of txtFiles) {
    const fileContent = await fetchFileContent(context, payload, file);
    if (fileContent) {
      // Ahora pasamos patterns y exclusions
      const fileVulnerabilities = detectSensitiveDataForPR(file, fileContent, context, patterns, exclusions);

      // Log detected vulnerabilities
      console.log(`Detected vulnerabilities in ${file}:`, fileVulnerabilities);

      if (fileVulnerabilities.length > 0) {
        vulnerabilities[file] = fileVulnerabilities;

        // Replace vulnerabilities with marker
        let updatedContent = fileContent;
        for (const vuln of fileVulnerabilities) {
          const escapedVuln = vuln.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const regex = new RegExp(escapedVuln, 'g');
          updatedContent = updatedContent.replace(regex, '[DELETED VULNERABILITY]');
        }

        // Log updated content
        console.log(`Updated content for ${file}:\n`, updatedContent);

        changes.push({
          path: file,
          content: Buffer.from(updatedContent).toString('base64'),
          originalSha: (await context.octokit.repos.getContent({
            owner: payload.repository.owner.login,
            repo: payload.repository.name,
            path: file,
          })).data.sha,
        });
      }
    }
  }

  if (Object.keys(vulnerabilities).length > 0) {
    // Create a new branch
    const baseBranchSha = (await context.octokit.repos.getBranch({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      branch: baseBranch,
    })).data.commit.sha;

    await context.octokit.git.createRef({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      ref: `refs/heads/${branchName}`,
      sha: baseBranchSha,
    });

    // Create a single commit with all changes
    for (const change of changes) {
      await context.octokit.repos.createOrUpdateFileContents({
        owner: payload.repository.owner.login,
        repo: payload.repository.name,
        path: change.path,
        message: `Remove sensitive data from ${change.path}`,
        content: change.content,
        branch: branchName,
        sha: change.originalSha,
      });
    }

    // Create a pull request
    await context.octokit.pulls.create({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      title: 'Remove sensitive data from text files',
      head: branchName,
      base: baseBranch,
      body: `This pull request removes sensitive data from the following files:\n\n${Object.keys(vulnerabilities)
        .map(file => `- ${file}`)
        .join('\n')}`,
    });

    context.log.info('Pull request created successfully');
  } else {
    context.log.info('No vulnerabilities found in text files');
  }
}