const fs = require('fs').promises;
const path = require('path');
const process = require('process');
const {authenticate} = require('@google-cloud/local-auth');
const {google} = require('googleapis');

// If modifying these scopes, delete token.json.
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

// The file token.json stores the user's access and refresh tokens, 
// It is created automatically when the authorization flow completes for the first time.
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');

// Reads previously authorized credentials from the save file.
async function loadSavedCredentialsIfExist() {
  try {
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content);
    return google.auth.fromJSON(credentials);
  } catch (err) {
    return null;
  }
}

// Serializes credentials to a file compatible with GoogleAuth.fromJSON.
async function saveCredentials(client) {
  const content = await fs.readFile(CREDENTIALS_PATH);
  const keys = JSON.parse(content);
  const key = keys.installed || keys.web;
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: key.client_id,
    client_secret: key.client_secret,
    refresh_token: client.credentials.refresh_token,
  });
  await fs.writeFile(TOKEN_PATH, payload);
}

// Load or request or authorization to call APIs.
async function authorize() {
  let client = await loadSavedCredentialsIfExist();
  if (client) {
    return client;
  }
  client = await authenticate({
    scopes: SCOPES,
    keyfilePath: CREDENTIALS_PATH,
  });
  if (client.credentials) {
    await saveCredentials(client);
  }
  return client;
}



// Extracting ID from the latest email
async function extractIDFromLatestEmail(auth) {
  const gmail = google.gmail({ version: 'v1', auth });

  // Fetch the latest email
  const res = await gmail.users.messages.list({ userId: 'me', maxResults: 1 });
  const latestEmailId = res.data.messages?.[0]?.id;

  // No email found
  if (!latestEmailId) {
    console.log('No emails found.');
    return;
  }

  // Latest email
  const latestEmail = await gmail.users.messages.get({ 
    userId: 'me', 
    id: latestEmailId,
  });
  const emailBody = Buffer.from(latestEmail.data.payload.parts[0].body.data, 'base64').toString();

  // Extract ID from the email body using Regex
  const idMatch = emailBody.match(/\b\d{8}\b/);

  // If ID is found
  if (idMatch) {
    const id = parseInt(idMatch[0]);
    console.log('Extracted ID:', id);
  } else {
    console.log('No ID found in the email body.');
  }
}


authorize().then(extractIDFromLatestEmail).catch(console.error);

