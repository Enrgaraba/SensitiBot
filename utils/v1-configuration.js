//PARA QUE NO SE PIERRDA LA INFORMACION
//SIN TERMINAR

import { Buffer } from "buffer";
import { 
  getModifiedFiles, 
  createIssue, 
  analyzeFilesWithPatterns, 
  createPullRequestToRemoveSensitiveData 
} from "./githubUtils.js";

/**
 * This is the main entrypoint to your Probot app
 * @param {import('probot').Probot} app
 */
const appFunction = (app) => {
  app.log.info("Yay, the app was loaded!");

  app.on("push", async (context) => {
    const branchRef = context.payload.ref; // formato: refs/heads/branch-name
    const branchName = branchRef.replace('refs/heads/', '');

    // Ignore pushes to bot-generated branches
    if (branchName.startsWith('remove-sensitive-data')) {
      context.log.info(`Ignoring push to bot-generated branch: ${branchName}`);
      return;
    }

    context.log.info("Push event received");

    // Read the configuration file from the repository
    const owner = context.payload.repository.owner.login;
    const repo = context.payload.repository.name;
    const filePath = "configuration-sensitibot.txt";

    let configContent = "";
    try {
      const fileContent = await context.octokit.repos.getContent({
        owner,
        repo,
        path: filePath,
      });

      // Decode the file content from Base64
      configContent = Buffer.from(fileContent.data.content, "base64").toString("utf-8");
      context.log.info("Configuration file content:", configContent);
    } catch (error) {
      context.log.error(`Error reading configuration file: ${error.message}`);
      return;
    }

    // Parse the configuration file
    const config = parseConfiguration(configContent);

    // Get the modified files in the push
    const { payload } = context;
    const files = getModifiedFiles(payload);
    context.log.info("Files in the push", files);

    // Filter files based on the configured file types
    const filteredFiles = files.filter(file => 
      config.fileTypes.some(ext => file.endsWith(ext))
    );

    // Analyze files for sensitive content based on patterns
    let vulnerabilities = await analyzeFilesWithPatterns(context, filteredFiles, config.patterns, config.exclusions);

    if (vulnerabilities.length > 0) {
      // Create an issue for the detected vulnerabilities
      await createIssue(context, vulnerabilities);

      // Take action based on the configuration
      if (config.onDetection === "Block" || config.onDetection === "Full") {
        await createPullRequestToRemoveSensitiveData(context, payload);
      }
    }
  });
};

export const parseConfiguration = (configContent) => {
    const config = {};
  
    // Extract patterns
    const patternsMatch = configContent.match(/PatternsList:\s*\[(.*?)\]/s);
    config.patterns = patternsMatch ? eval(`[${patternsMatch[1]}]`) : [];
  
    // Extract file types
    const fileTypesMatch = configContent.match(/FileTypes:\s*\[(.*?)\]/s);
    config.fileTypes = fileTypesMatch ? eval(`[${fileTypesMatch[1]}]`) : [];
  
    // Extract onDetection action
    const onDetectionMatch = configContent.match(/OnDetection:\s*(\w+)/);
    config.onDetection = onDetectionMatch ? onDetectionMatch[1] : "Alert";
  
    // Extract exclusions
    const exclusionsMatch = configContent.match(/Exclusions:\s*\[(.*?)\]/s);
    config.exclusions = exclusionsMatch ? eval(`[${exclusionsMatch[1]}]`) : [];
  
    return config;
  };

  export const analyzeFilesWithPatterns = async (context, files, patterns, exclusions) => {
    let vulnerabilities = [];
  
    for (const file of files) {
      const fileContent = await getFileContent(context, file);
  
      for (const [label, pattern] of patterns) {
        const regex = new RegExp(pattern, "g");
        const matches = fileContent.match(regex);
  
        if (matches) {
          const filteredMatches = matches.filter(match => !exclusions.includes(match));
          if (filteredMatches.length > 0) {
            vulnerabilities.push({
              file,
              label,
              matches: filteredMatches,
            });
          }
        }
      }
    }
  
    return vulnerabilities;
  };
export default appFunction;