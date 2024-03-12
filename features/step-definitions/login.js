const { Given, When, Then } = require('@cucumber/cucumber');
const LoginPage = require('../pageobjects/login');

Given(/^I am on the login page$/, async () => {
    await browser.url('https://accounts.google.com/signin/v2/identifier');
});

When(/^I login with (.+) and (.+)$/, async (email, password) => {
    await browser.pause(1500);
    await LoginPage.enterEmail(email);
    await browser.pause(1500);
    await LoginPage.clickNext();
    await browser.pause(1500);
    await LoginPage.enterPassword(email);
    await browser.pause(1500);
    await LoginPage.clickNext();
});

Then(/^I should see a flash message that starts with (.+)$/, async (message) => {
    // await HomePage.open();
    // await expect(HomePage.welcomeMessage).toBeExisting();
    // await expect(HomePage.welcomeMessage).toHaveTextContaining(message);
});