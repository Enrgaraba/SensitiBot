import { fetchFileContent } from "./fileUtils.js";
import {
  detectSensitiveDataTxt,
  detectSensitiveDataCsv,
  detectSensitiveDataForPR,
  detectSensitiveDataMd,
  detectSensitiveDataJson,
  detectSensitiveDataYaml
} from "./securityPatterns.js";

/**
 * Gets the list of modified files, excluding the configuration file.
 * @param {object} payload - GitHub webhook payload.
 * @returns {string[]} - Array of modified file paths.
 */
export function getModifiedFiles(payload) {
  // Exclude the configuration file from the list of modified files
  const configFile = "configuration-sensitibot.txt";
  return payload.commits
    .flatMap(commit => commit.added.concat(commit.modified))
    .filter(file => !file.endsWith(configFile));
}

/**
 * Analyzes .txt files for sensitive data.
 * @param {object} context - Probot context object.
 * @param {object} payload - GitHub webhook payload.
 * @param {string[]} files - List of files to analyze.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Promise<Array>} - Array of vulnerabilities found.
 */
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

/**
 * Analyzes .csv files for sensitive data.
 * @param {object} context - Probot context object.
 * @param {object} payload - GitHub webhook payload.
 * @param {string[]} files - List of files to analyze.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Promise<Array>} - Array of vulnerabilities found.
 */
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

/**
 * Analyzes .md files for sensitive data.
 * @param {object} context - Probot context object.
 * @param {object} payload - GitHub webhook payload.
 * @param {string[]} files - List of files to analyze.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Promise<Array>} - Array of vulnerabilities found.
 */
export async function analyzeMdFiles(context, payload, files, patterns, exclusions) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.md')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const detected = detectSensitiveDataMd(fileContent, patterns, exclusions);
        for (const { label, matches } of detected) {
          vulnerabilities.push({ file, label, matches });
        }
      }
    }
  }
  return vulnerabilities;
}

/**
 * Analyzes .json files for sensitive data.
 * @param {object} context - Probot context object.
 * @param {object} payload - GitHub webhook payload.
 * @param {string[]} files - List of files to analyze.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Promise<Array>} - Array of vulnerabilities found.
 */
export async function analyzeJsonFiles(context, payload, files, patterns, exclusions) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.json')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const detected = detectSensitiveDataJson(fileContent, patterns, exclusions);
        for (const { label, matches } of detected) {
          vulnerabilities.push({ file, label, matches });
        }
      }
    }
  }
  return vulnerabilities;
}

/**
 * Analyzes .yaml and .yml files for sensitive data.
 * @param {object} context - Probot context object.
 * @param {object} payload - GitHub webhook payload.
 * @param {string[]} files - List of files to analyze.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Promise<Array>} - Array of vulnerabilities found.
 */
export async function analyzeYamlFiles(context, payload, files, patterns, exclusions) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.yaml') || file.endsWith('.yml')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const detected = detectSensitiveDataYaml(fileContent, patterns, exclusions);
        for (const { label, matches } of detected) {
          vulnerabilities.push({ file, label, matches });
        }
      }
    }
  }
  return vulnerabilities;
}

/**
 * Creates a GitHub issue for found vulnerabilities.
 * @param {object} context - Probot context object.
 * @param {Array} vulnerabilities - Array of vulnerabilities found.
 * @returns {Promise<void>}
 */
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

/**
 * Creates a GitHub issue for vulnerabilities found by Gemini.
 * @param {object} context - Probot context object.
 * @param {Array} vulnerabilities - Array of vulnerabilities found.
 * @returns {Promise<void>}
 */
export async function createIssueGemini(context, vulnerabilities) {
  const body = vulnerabilities
    .map(vuln => `In **${vuln.file}** (${vuln.label}) ${vuln.matches.join(', ')}`)
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

/**
 * Creates a pull request to remove sensitive data from files.
 * @param {object} context - Probot context object.
 * @param {object} payload - GitHub webhook payload.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @param {Array} fileTypes - Supported file types.
 * @param {string} trustBadge - Trust badge configuration.
 * @returns {Promise<void>}
 */
export async function createPullRequestToRemoveSensitiveData(context, payload, patterns, exclusions, fileTypes, trustBadge) {
  const branchName = `remove-sensitive-data-${Date.now()}`;
  const baseBranch = payload.repository.default_branch;
  const modifiedFiles = getModifiedFiles(payload);
  console.log(`File Types: ${fileTypes.join(', ')}`);
  console.log(`modifiedFiles: ${modifiedFiles.join(', ')}`);

  // Soportar todos los tipos de archivos
  const supportedExtensions = [
    { ext: '.txt', type: 'txt' },
    { ext: '.csv', type: 'csv' },
    { ext: '.md', type: 'md' },
    { ext: '.json', type: 'json' },
    { ext: '.yaml', type: 'yaml' },
    { ext: '.yml', type: 'yml' }
  ];

  const vulnerabilities = {};
  const changes = [];

  for (const file of modifiedFiles) {
    const extObj = supportedExtensions.find(e => file.endsWith(e.ext));
    console.log(`Processing file: ${file}, extension object:`, extObj);
    if (!extObj) continue;
    console.log(`File type detected: ${extObj.type}`);
    
    if (!fileTypes.includes(extObj.type)) continue;

    const fileContent = await fetchFileContent(context, payload, file);
    console.log(`Fetched content for ${file}:`, fileContent ? 'Content retrieved' : 'No content found');
    if (fileContent) {
      
      const fileVulnerabilities = detectSensitiveDataForPR(
        file,
        fileContent,
        context,
        patterns,
        exclusions,
        extObj.type,
        fileTypes
      );

      console.log(`Detected vulnerabilities in ${file}:`, fileVulnerabilities);

      // Filtra solo los objetos con matches reales
      if (fileVulnerabilities.length > 0) {
        vulnerabilities[file] = fileVulnerabilities;
        let updatedContent = fileContent;

        // Badge logic based on trustBadge config
        const shouldAddBadge =
          trustBadge === "fullbadge" ||
          (trustBadge === "nojson" && extObj.type !== "json");

        if (shouldAddBadge) {
          if (file.endsWith('.json')) {
            try {
              const jsonObj = JSON.parse(fileContent);
              if (!jsonObj._sensitibot_validated) {
                jsonObj._sensitibot_validated = "✅ Validated by SensitiBot: No vulnerabilities found";
              }
              updatedContent = JSON.stringify(jsonObj, null, 2);
            } catch (e) {
              updatedContent = fileContent;
            }
          } else if (file.endsWith('.yaml') || file.endsWith('.yml')) {
            const validationBadge = '# ✅ Validated by SensitiBot: No vulnerabilities found\n';
            if (!updatedContent.startsWith(validationBadge)) {
              updatedContent = validationBadge + updatedContent;
            }
          } else if (file.endsWith('.md')) {
            const validationBadge = '> ✅ Validated by SensitiBot: No vulnerabilities found\n\n';
            if (!updatedContent.startsWith(validationBadge)) {
              updatedContent = validationBadge + updatedContent;
            }
          } else if (file.endsWith('.csv') || file.endsWith('.txt')) {
            const validationBadge = '# ✅ Validated by SensitiBot: No vulnerabilities found\n';
            updatedContent = validationBadge + updatedContent;
          }
        }

        for (const vuln of fileVulnerabilities) {
          if (Array.isArray(vuln.matches)) {
            for (const m of vuln.matches) {
              const escapedVuln = m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
              const regex = new RegExp(escapedVuln, 'g');
              updatedContent = updatedContent.replace(regex, '[DELETED VULNERABILITY]');
            }
          }
        }

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
      title: 'Remove sensitive data from files',
      head: branchName,
      base: baseBranch,
      body: `This pull request removes sensitive data from the following files:\n\n${Object.keys(vulnerabilities)
        .map(file => `- ${file}`)
        .join('\n')}`,
    });

    context.log.info('Pull request created successfully');
  } else {
    context.log.info('No vulnerabilities found in supported files');
  }
}