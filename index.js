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

    // Separate files by type
    const txtFiles = filteredFiles.filter(file => file.endsWith('.txt'));
    const csvFiles = filteredFiles.filter(file => file.endsWith('.csv'));

    let vulnerabilities = [];

    if (txtFiles.length > 0) {
      vulnerabilities = vulnerabilities.concat(
        await analyzeTxtFiles(context, payload, txtFiles, config.patterns, config.exclusions)
      );
    }
    if (csvFiles.length > 0) {
      vulnerabilities = vulnerabilities.concat(
        await analyzeCsvFiles(context, payload, csvFiles, config.patterns, config.exclusions)
      );
    }

    if (vulnerabilities.length > 0) {
      if (config.onDetection === "Alert" || config.onDetection === "Full") {
        await createIssue(context, vulnerabilities);
      }
      if (config.onDetection === "Block" || config.onDetection === "Full") {
        await createPullRequestToRemoveSensitiveData(context, payload);
      }
    }
  });
};

export default appFunction;