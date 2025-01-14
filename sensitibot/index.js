

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
          owner: payload.repository.owner.name,
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

      // Create a transporter object using the default SMTP transport
      let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'your-email@gmail.com', // replace with your email
          pass: 'your-email-password' // replace with your email password
        }
      });

      // Setup email data
      let mailOptions = {
        from: '"SensitiBot" <your-email@gmail.com>', // sender address
        to: payload.repository.owner.email, // list of receivers
        subject: 'Vulnerabilities found in your repository', // Subject line
        text: `The following vulnerabilities were found in your repository:\n\n${vulnerabilities.map(v => `File: ${v.file}\nIssues: ${v.issues.join(', ')}\n`).join('\n')}` // plain text body
      };

      // Send mail with defined transport object
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return app.log.error('Error sending email:', error);
        }
        app.log.info('Email sent:', info.response);
      });
    }
  });

  // For more information on building apps:
  // https://probot.github.io/docs/

  // To get your app running against GitHub, see:
  // https://probot.github.io/docs/development/
};
