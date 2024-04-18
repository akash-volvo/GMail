// Importing necessary modules
const { google } = require('googleapis');
const fs = require('fs');
const readline = require('readline');

class EmailExtractor {
  constructor() {
    // Scopes required for Gmail API access
    this.SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
  }

  // Method to authorize access using OAuth2
  async authorize() {
    // Load client credentials
    const credentials = JSON.parse(fs.readFileSync('credentials.json'));
    const { client_secret, client_id } = credentials.installed;
    // Create OAuth2 client
    const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, "urn:ietf:wg:oauth:2.0:oob");

    try {
      // Load token from file if available
      const token = JSON.parse(fs.readFileSync('token.json'));
      oAuth2Client.setCredentials(token);
      // Return authorized client
      return oAuth2Client;
    } catch (error) {
      // Get new token if not available
      return await this.getNewToken(oAuth2Client);
    }
  }

  // Method to get a new access token
  async getNewToken(oAuth2Client) {
    const authUrl = oAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: this.SCOPES,
    });
    // Prompt user to authorize app
    console.log('Authorize this app by visiting this URL:', authUrl);
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    return new Promise((resolve, reject) => {
      // Prompt user for authorization code
      rl.question('Enter the code from that page here: ', (code) => {
        rl.close();
        oAuth2Client.getToken(code, (err, token) => {
          if (err) {
            console.error('Error retrieving access token', err);
            reject(err);
          } else {
            oAuth2Client.setCredentials(token);
            // Save token to file
            fs.writeFileSync('token.json', JSON.stringify(token));
            resolve(oAuth2Client);
          }
        });
      });
    });
  }

  // Method to extract the latest email's ID
  async extractLatestEmail(auth) {
    const gmail = google.gmail({ version: 'v1', auth });
    const res = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 1,
      q: `from:noreply@volvocars.com`,
    });
    const latestEmailId = res.data.messages?.[0]?.id;
    if (!latestEmailId) {
      throw new Error('No emails found from the specified sender.');
    }
    const latestEmail = await gmail.users.messages.get({ userId: 'me', id: latestEmailId });
    
    // Extract the email body from the payload and decode it
    const emailBody = Buffer.from(latestEmail.data.payload.parts[0].body.data, 'base64').toString();
  
    // Extract the email subject
    const emailSubject = latestEmail.data.payload.headers.find(
      (header) => header.name === 'Subject'
    )?.value || '';
  
    // Combine email body and subject for ID extraction
    const combinedContent = `${emailSubject} ${emailBody}`;
  
    // Regex to get the ID
    const idPattern = /\b\d{8}\b/;
    const match = combinedContent.match(idPattern);
    if (!match) {
      throw new Error('No ID found in the email body or subject.');
    }
  
    const extractedId = match[0];
    console.log(`Extracted ID from email body or subject: ${extractedId}`);
    return extractedId;
  }

  // Method to initiate the email extraction process
  async processEmailAndExtractCaseNumber() {
    try {
      // Authorize access
      const auth = await this.authorize();
      // Extract ID from latest email
      return await this.extractLatestEmail(auth);
    } catch (error) {
      console.error(`Error while extracting ID from the latest email body: ${error}`);
      return null;
    }
  }
}

const extractor = new EmailExtractor();
// Start the extraction process
extractor.processEmailAndExtractCaseNumber();
