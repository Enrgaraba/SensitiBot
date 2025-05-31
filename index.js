import { 
  getModifiedFiles, 
  createIssue, 
  analyzeCsvFiles, 
  analyzeTxtFiles, 
  createPullRequestToRemoveSensitiveData 
} from "./utils/githubUtils.js";
import { parseConfiguration } from "./utils/fileUtils.js";
import { Buffer } from "buffer";

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
      console.log("DEBUG: Raw config content:", configContent);
    } catch (error) {
      context.log.error(`Error reading configuration file: ${error.message}`);
      console.error("DEBUG: Error reading configuration file:", error);
      return;
    }

    // Parse the configuration file
    let config;
    try {
      config = parseConfiguration(configContent);
      context.log.info("Parsed configuration:", config);
      console.log("DEBUG: Parsed config object:", config);
    } catch (error) {
      context.log.error(`Error parsing configuration file: ${error.message}`);
      console.error("DEBUG: Error parsing configuration file:", error);
      return;
    }

    // Get the modified files in the push
    const { payload } = context;
    const files = getModifiedFiles(payload);
    context.log.info("Files in the push", files);
    console.log("DEBUG: Files in the push:", files);

    // Filter files based on the configured file types
    const filteredFiles = files.filter(file => 
      config.fileTypes.some(ext => file.endsWith(ext))
    );
    context.log.info("Filtered files by type:", filteredFiles);
    console.log("DEBUG: Filtered files by type:", filteredFiles);

    // Separate files by type
    const txtFiles = filteredFiles.filter(file => file.endsWith('.txt'));
    const csvFiles = filteredFiles.filter(file => file.endsWith('.csv'));
    console.log("DEBUG: TXT files:", txtFiles);
    console.log("DEBUG: CSV files:", csvFiles);

    let vulnerabilities = [];

    if (txtFiles.length > 0) {
      const txtVulns = await analyzeTxtFiles(context, payload, txtFiles, config.patterns, config.exclusions);
      console.log("DEBUG: TXT vulnerabilities:", txtVulns);
      vulnerabilities = vulnerabilities.concat(txtVulns);
    }
    if (csvFiles.length > 0) {
      const csvVulns = await analyzeCsvFiles(context, payload, csvFiles, config.patterns, config.exclusions);
      console.log("DEBUG: CSV vulnerabilities:", csvVulns);
      vulnerabilities = vulnerabilities.concat(csvVulns);
    }

    console.log("DEBUG: All vulnerabilities found:", vulnerabilities);

    if (vulnerabilities.length > 0) {
      if (config.onDetection === "Alert" || config.onDetection === "Full") {
        console.log("DEBUG: Creating issue for vulnerabilities...");
        await createIssue(context, vulnerabilities);
      }
      if (config.onDetection === "Block" || config.onDetection === "Full") {
        console.log("DEBUG: Creating PR to remove sensitive data...");
        await createPullRequestToRemoveSensitiveData(context, payload, config.patterns, config.exclusions);
      }
    } else {
      console.log("DEBUG: No vulnerabilities found.");
    }
  });
};

export default appFunction;