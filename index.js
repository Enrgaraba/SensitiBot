import { 
  getModifiedFiles, 
  createIssue, 
  analyzeCsvFiles, 
  analyzeTxtFiles, 
  analyzeMdFiles,
  analyzeJsonFiles,
  analyzeYamlFiles,
  createPullRequestToRemoveSensitiveData, 
  createIssueGemini
} from "./utils/githubUtils.js";
import { parseConfiguration } from "./utils/fileUtils.js";
import { detectSensitiveDataWithGemini } from "./utils/securityPatterns.js"; // <-- Importa la función Gemini
import { Buffer } from "buffer";

/**
 * This is the main entrypoint to your Probot app
 * @param {import('probot').Probot} app
 */
const appFunction = (app) => {
  app.log.info("Yay, the app was loaded!");

  app.on("push", async (context) => {
    const branchRef = context.payload.ref; 
    const branchName = branchRef.replace('refs/heads/', '');

    // Ignore pushes to bot-generated branches
    if (branchName.startsWith('remove-sensitive-data')) {
      context.log.info(`Ignoring push to bot-generated branch: ${branchName}`);
      return;
    }

    context.log.info("Push event received");

    // Load configuration file from repository
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
      configContent = Buffer.from(fileContent.data.content, "base64").toString("utf-8");
      context.log.info("Configuration file content:", configContent);
    } catch (error) {
      context.log.error(`Configuration file missing, the bot will use default values: ${error.message}`);
      // Continue with empty configContent (default values)
    }

    // Parse the configuration file
    let config;
    try {
      config = parseConfiguration(configContent);
      context.log.info("Parsed configuration:", config);
      
    } catch (error) {
      context.log.error(`Error parsing configuration file: ${error.message}`);
      
      return;
    }

    // Get the modified files in the push
    const { payload } = context;
    const files = getModifiedFiles(payload);
    context.log.info("Files in the push", files);
    

    // Filter files based on the configured file types
    const filteredFiles = files.filter(file => 
      config.fileTypes.some(ext => file.endsWith(ext))
    );
    context.log.info("Filtered files by type:", filteredFiles);
    

    // Separate files by type
    const txtFiles = filteredFiles.filter(file => file.endsWith('.txt'));
    const csvFiles = filteredFiles.filter(file => file.endsWith('.csv'));
    const mdFiles = filteredFiles.filter(file => file.endsWith('.md'));
    const jsonFiles = filteredFiles.filter(file => file.endsWith('.json'));
    const yamlFiles = filteredFiles.filter(file => file.endsWith('.yaml') || file.endsWith('.yml'));
    
    let vulnerabilities = [];

    // Analyze each type of file for sensitive data by using the configured patterns and exclusions
    
    if (txtFiles.length > 0) {
      const txtVulns = await analyzeTxtFiles(context, payload, txtFiles, config.patterns, config.exclusions);
      
      vulnerabilities = vulnerabilities.concat(txtVulns);
    }
    if (csvFiles.length > 0) {
      const csvVulns = await analyzeCsvFiles(context, payload, csvFiles, config.patterns, config.exclusions);
      
      vulnerabilities = vulnerabilities.concat(csvVulns);
    }
    if (mdFiles.length > 0) {
      const mdVulns = await analyzeMdFiles(context, payload, mdFiles, config.patterns, config.exclusions);
      
      vulnerabilities = vulnerabilities.concat(mdVulns);
    }
    if (jsonFiles.length > 0) {
      const jsonVulns = await analyzeJsonFiles(context, payload, jsonFiles, config.patterns, config.exclusions);
      
      vulnerabilities = vulnerabilities.concat(jsonVulns);
    }
    if (yamlFiles.length > 0) {
      const yamlVulns = await analyzeYamlFiles(context, payload, yamlFiles, config.patterns, config.exclusions);
      
      vulnerabilities = vulnerabilities.concat(yamlVulns);
    }
    

    // If the detection engine is Gemini, add its results ONLY for issue creation
    let geminiVulnerabilities = [];
    if (config.detectionEngine === "gemini") {
      for (const file of filteredFiles) {
        const fileContent = await context.octokit.repos.getContent({
          owner,
          repo,
          path: file,
        });
        const content = Buffer.from(fileContent.data.content, "base64").toString("utf-8");
        const type = file.split('.').pop();
        try {
          const geminiResult = await detectSensitiveDataWithGemini(
            content,
            type,
            process.env.GEMINI_API_KEY,
            config.geminiPrompt
          );
          if (!geminiResult.includes("No se detectó contenido sensible")) {
            geminiVulnerabilities.push({ file, label: "Gemini", matches: [geminiResult] });
          }
        } catch (e) {
          console.error("DEBUG: Gemini API error:", e);
        }
      }
    }



    if (vulnerabilities.length > 0 || geminiVulnerabilities.length > 0) {
      if (config.onDetection === "Alert" || config.onDetection === "Full") {
        if (config.detectionEngine === "gemini") {
          await createIssueGemini(context, geminiVulnerabilities);
        } else {
          await createIssue(context, vulnerabilities);
        }
      }
      if (
        vulnerabilities.length > 0 &&
        (config.onDetection === "Block" || config.onDetection === "Full")
      ) {
        await createPullRequestToRemoveSensitiveData(
          context,
          payload,
          config.patterns,
          config.exclusions,
          config.fileTypes,
          config.trustBadge
        );
      }
    } else {
      console.log("DEBUG: No vulnerabilities found.");
    }
  });
};

export default appFunction;