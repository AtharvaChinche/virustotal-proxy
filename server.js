const puppeteer = require("puppeteer");

async function getWebsiteInfo(url) {
    console.log("🌍 Fetching website info for:", url);
    try {
        const browser = await puppeteer.launch({
            headless: "new",
            args: ["--no-sandbox", "--disable-setuid-sandbox"] // ✅ Prevents Render memory issues
        });
        const page = await browser.newPage();
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });

        const finalURL = page.url();
        const title = await page.title();
        const description = await page.$eval("meta[name='description']", el => el.content).catch(() => "No description found");

        await browser.close();
        return { finalURL, title, description };
    } catch (error) {
        console.error("❌ Error fetching website info:", error.message);
        return { finalURL: url, title: "Error fetching site", description: "Error fetching details" };
    }
}
