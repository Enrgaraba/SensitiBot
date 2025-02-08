import Papa from "papaparse";
import { fetchFileContent } from "./fileUtils.js";
import { detectSensitiveDataTxt, detectSensitiveDataCsv } from "./securityPatterns.js";

export function getModifiedFiles(payload) {
  return payload.commits.flatMap(commit => commit.added.concat(commit.modified));
}

export async function analyzeTxtFiles(context, payload, files) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.txt')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const fileVulnerabilities = detectSensitiveDataTxt(file, fileContent, context);
        if (fileVulnerabilities.length > 0) {
          vulnerabilities.push({ file, issues: fileVulnerabilities });
        }
      }
    }
  }
  return vulnerabilities;
}

export async function analyzeCsvFiles(context, payload, files) {
  const vulnerabilities = [];
  for (const file of files) {
    if (file.endsWith('.csv')) {
      const fileContent = await fetchFileContent(context, payload, file);
      if (fileContent) {
        const parsedData = Papa.parse(fileContent, { header: false, skipEmptyLines: "greedy" });
        let fileVulnerabilities = [];

        for (const row of parsedData.data) {
          if (row.some(cell => detectSensitiveDataCsv(file, cell, context).length > 0)) {
            fileVulnerabilities.push(...detectSensitiveDataCsv(file, row.join(','), context));
          }
        }

        if (fileVulnerabilities.length > 0) {
          vulnerabilities.push({ file, issues: [...new Set(fileVulnerabilities)] });
        }
      }
    }
  }
  return vulnerabilities;
}

export async function createIssue(context, vulnerabilities) {
  const body = vulnerabilities.map(vuln => `**${vuln.file}** contains: ${vuln.issues.join(', ')}`).join('\n');
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
