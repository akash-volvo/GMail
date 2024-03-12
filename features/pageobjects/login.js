const { $ } = require('@wdio/globals');
const Page = require('./page');

class LoginPage extends Page {
    get emailInput() { return $('[name="identifier"]'); }
    // Old
    // get nextButton() { return $('button.VfPpkd-LgbsSe.VfPpkd-LgbsSe-OWXEXe-k8QpJ.VfPpkd-LgbsSe-OWXEXe-dgl2Hf.nCP5yc.AjY5Oe.DuMIQc.LQeN7.qIypjc.TrZEUc.lw1w4b[jsname="LgbsSe"]'); } 
    // New
    get nextButton() { return $('.VfPpkd-LgbsSe.VfPpkd-LgbsSe-OWXEXe-k8QpJ.VfPpkd-LgbsSe-OWXEXe-dgl2Hf.nCP5yc.AjY5Oe.DuMIQc.LQeN7.BqKGqe.Jskylb.TrZEUc.lw1w4b'); } 
    get passwordInput() { return $('[name="Passwd"]'); }
    
    async enterEmail(email) {
        await this.emailInput.setValue(email);
    }

    async enterPassword(password) {
        await this.passwordInput.setValue(password);
    }

    async clickNext() {
        await this.nextButton.click();
    }
}

module.exports = new LoginPage();
