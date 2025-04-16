import { 
  getModifiedFiles, 
  createIssue, 
  analyzeCsvFiles, 
  analyzeTxtFiles, 
  createPullRequestToRemoveSensitiveData 
} from "./utils/githubUtils.js";

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
    
    const { payload } = context;
    context.log.info("Payload", payload);
    
    const files = getModifiedFiles(payload);
    context.log.info("Files in the push", files);
    
    let vulnerabilities = [];
    const txtVulnerabilities = await analyzeTxtFiles(context, payload, files);
    vulnerabilities = vulnerabilities.concat(txtVulnerabilities);
    vulnerabilities = vulnerabilities.concat(await analyzeCsvFiles(context, payload, files));
    
    if (vulnerabilities.length > 0) {
      // Create an issue for the detected vulnerabilities
      await createIssue(context, vulnerabilities);

      // Create a single pull request for all changes
      await createPullRequestToRemoveSensitiveData(context, payload, vulnerabilities);
    }
  });
};

export default appFunction;