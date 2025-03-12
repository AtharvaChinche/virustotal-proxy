const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const puppeteer = require("puppeteer"); // ✅ Use Puppeteer to get full page content
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 10000;
const GOOGLE_API_KEY = process.env.API_KEY;

// ✅ Function to check if the input is a valid URL
function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// ✅ Function to fetch full page content using Puppeteer
async function getWebsiteSummary(url) {
    console.log("🌍 Fetching website info for:", url);
    try {
        const browser = await puppeteer.launch({
            headless: "new",
            args: ["--no-sandbox", "--disable-setuid-sandbox"] // ✅ Fixes Render issues
        });

        const page = await browser.newPage();
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });

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

// ✅ API Endpoint to check a URL
app.post("/check-url", async (req, res) => {
    try {
        const { url } = req.body;

        if (!url || !isValidURL(url)) {
            return res.status(400).json({ error: "❌ Invalid request: Please enter a valid URL." });
        }

        console.log("📤 Checking URL:", url);

        // ✅ Step 1: Check Google Safe Browsing
        const requestBody = {
            client: { clientId: "yourcompany", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };

        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        // ✅ Step 2: Get Website Summary (Now Uses Puppeteer)
        const websiteInfo = await getWebsiteSummary(url);

        let result = {
            originalURL: url,
            finalURL: websiteInfo.finalURL,
            title: websiteInfo.title,
            description: websiteInfo.description
        };

        // ✅ Step 3: Return Safe or Threat Info
        if (data && data.matches && data.matches.length > 0) {
            result.safe = false;
            result.threats = data.matches.map(match => ({
                type: match.threatType,
                platform: match.platformType,
                url: match.threat.url
            }));
        } else {
            result.safe = true;
            result.message = "✅ No threats found!";
        }

        res.json(result);
    } catch (error) {
        res.status(500).json({ error: "❌ Internal Server Error" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
