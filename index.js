
import { getModifiedFiles, createIssue, analyzeCsvFiles, analyzeTxtFiles } from "./utils/githubUtils.js";

/**
 * This is the main entrypoint to your Probot app
 * @param {import('probot').Probot} app
 */
module.exports = (app) => {
  app.log.info("Yay, the app was loaded!");

  app.on("push", async (context) => {
    app.log.info("Push event received");
    
    const { payload } = context;
    app.log.info("Payload", payload);
    
    const files = getModifiedFiles(payload);
    app.log.info("Files in the push", files);
    
    let vulnerabilities = [];
    vulnerabilities = vulnerabilities.concat(await analyzeTxtFiles(context, payload, files));
    vulnerabilities = vulnerabilities.concat(await analyzeCsvFiles(context, payload, files));
    
    if (vulnerabilities.length > 0) {
      await createIssue(context, vulnerabilities);
    }
  });
};