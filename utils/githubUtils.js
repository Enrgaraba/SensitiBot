import Papa from "papaparse";
import { fetchFileContent } from "./fileUtils.js";
import { detectSensitiveDataTxt, detectSensitiveDataCsv, patterns } from "./securityPatterns.js";

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
  const body = vulnerabilities
    .map(vuln => `**${vuln.file}** contains: ${vuln.issues.join(', ')}`)
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

export async function createPullRequestToRemoveSensitiveData(context, payload, vulnerabilities) {
  const baseBranch = payload.ref.replace('refs/heads/', '');
  const repo = context.repo();

  try {
    console.log('Starting pull request creation process...');
    console.log('Base branch:', baseBranch);
    console.log('Repository:', repo);

    // Buscar si existe ya un PR abierto con una rama que comience con "remove-sensitive-data"
    const { data: existingPRs } = await context.octokit.pulls.list({
      ...repo,
      state: 'open',
    });

    let existingBranch = null;
    let existingPRNumber = null;
    for (const pr of existingPRs) {
      if (pr.head.ref.startsWith('remove-sensitive-data')) {
        existingBranch = pr.head.ref;
        existingPRNumber = pr.number;
        break;
      }
    }

    // Si ya existe, reutilizamos esa rama; si no, se crea una nueva
    const branchName = existingBranch || `remove-sensitive-data-${Date.now()}`;

    // Si la rama no existe, créala
    if (!existingBranch) {
      // Obtener la referencia de la rama base
      const { data: reference } = await context.octokit.git.getRef({
        ...repo,
        ref: `heads/${baseBranch}`,
      });
      console.log('Base branch reference:', reference);

      // Crear la nueva rama a partir de la base
      await context.octokit.git.createRef({
        ...repo,
        ref: `refs/heads/${branchName}`,
        sha: reference.object.sha,
      });
      console.log(`Created new branch: ${branchName}`);
    } else {
      console.log(`Reusing existing bot branch: ${branchName}`);
    }

    // Consolidar los cambios para todos los archivos en la misma rama
    for (const { file, issues } of vulnerabilities) {
      if (file.endsWith('.txt')) {
        console.log(`Processing file: ${file}`);
        const fileContent = await fetchFileContent(context, payload, file);
        if (fileContent) {
          console.log(`Original content of ${file}:`, fileContent);

          let updatedContent = fileContent;

          // Reemplazar datos sensibles con [REDACTED]
          // Para cada issue, se busca el patrón correspondiente
          for (const issue of issues) {
            const regex = Object.values(patterns).find((pattern) => pattern.test(fileContent));
            if (regex) {
              console.log(`Replacing sensitive data matching pattern: ${regex}`);
              updatedContent = updatedContent.replace(regex, '[REDACTED]');
            }
          }

          console.log(`Updated content of ${file}:`, updatedContent);

          // Obtener el contenido actual del archivo (de la rama base)
          const { data: fileData } = await context.octokit.repos.getContent({
            ...repo,
            path: file,
            ref: baseBranch,
          });
          console.log(`File data for ${file}:`, fileData);

          // Actualizar el contenido del archivo en la rama (nueva o existente)
          await context.octokit.repos.createOrUpdateFileContents({
            ...repo,
            path: file,
            message: `Remove sensitive data from ${file}`,
            content: Buffer.from(updatedContent).toString('base64'),
            branch: branchName,
            sha: fileData.sha,
          });

          console.log(`Updated file in branch ${branchName}: ${file}`);
        } else {
          console.log(`Failed to fetch content for file: ${file}`);
        }
      }
    }

    // Si ya se había creado un PR, podemos optar por actualizar su título o comentario
    if (existingBranch) {
      console.log(`Updating existing pull request #${existingPRNumber}`);
      // Opcional: actualizar título o dejar un comentario para avisar de que se han agregado nuevos cambios
      await context.octokit.pulls.update({
        ...repo,
        pull_number: existingPRNumber,
        title: 'Update: Remove sensitive data from .txt files',
      });
      console.log(`Pull request updated successfully: ${existingPRNumber}`);
    } else {
      // Si no existe, crear un nuevo pull request
      console.log('Creating pull request...');
      const { data: pullRequest } = await context.octokit.pulls.create({
        ...repo,
        title: 'Remove sensitive data from .txt files',
        head: branchName,
        base: baseBranch,
        body: 'This pull request removes sensitive data found in .txt files across multiple files.',
      });
      console.log(`Pull request created successfully: ${pullRequest.html_url}`);
    }
  } catch (error) {
    console.error('Error during pull request creation:', error);
  }
}
