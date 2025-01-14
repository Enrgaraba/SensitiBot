/**
 * This is the main entrypoint to your Probot app
 * @param {import('probot').Probot} app
 */
export default (app) => {
  // Your code here
  app.log.info("Yay, the app was loaded!");

  app.on("push", async (context) => {
    app.log.info("Push event received");
    const { payload } = context;
    app.log.info("Payload", payload);

    const files = payload.commits.flatMap(commit => commit.added.concat(commit.modified));
    app.log.info("Files in the push", files);

    const vulnerabilities = [];

    // Aqui se analiza cada uno de los archivos modificados o añadidos
    for (const file of files) {
      if (file.endsWith('.txt')) {
        const content = await context.octokit.repos.getContent({
          owner: payload.repository.owner.login,
          repo: payload.repository.name,
          path: file,
          ref: payload.ref
        });

        const fileContent = Buffer.from(content.data.content, 'base64').toString('utf-8');
        app.log.info(`Content of ${file}:`, fileContent);
        
        // Add your analysis logic here
        const phonePattern = /\b\d{3} \d{2} \d{2} \d{2}\b/;
        const cardPattern = /\b(?:\d[ -]*?){13,16}\b/;
        const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;

        let fileVulnerabilities = [];

        if (phonePattern.test(fileContent)) {
          app.log.warn(`Phone number found in ${file}`);
          fileVulnerabilities.push('Phone number');
        }
        if (cardPattern.test(fileContent)) {
          app.log.warn(`Credit card number found in ${file}`);
          fileVulnerabilities.push('Credit card number');
        }
        if (emailPattern.test(fileContent)) {
          app.log.warn(`Email address found in ${file}`);
          fileVulnerabilities.push('Email address');
        }

        if (fileVulnerabilities.length > 0) {
          vulnerabilities.push({ file, issues: fileVulnerabilities });
        }
      }
    }

    if (vulnerabilities.length > 0) {

      const body = vulnerabilities.map(vulnerability => {
        return `**${vulnerability.file}** contains the following sensitive information: ${vulnerability.issues.join(', ')}`;
      }).join('\n');

      const issue = context.issue({
        title: 'Sensitive information found',
        body
      });

      try {
        console.log('Creating issue with body:', body);
        await context.octokit.issues.create(issue);
        console.log('Issue created successfully');
      } catch (error) {
        console.error('Error creating issue:', error);
      }
    }
  });

  // For more information on building apps:
  // https://probot.github.io/docs/

  // To get your app running against GitHub, see:
};
