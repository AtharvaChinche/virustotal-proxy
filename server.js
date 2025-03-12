const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const puppeteer = require("puppeteer-core");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 10000;
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY; // ✅ Ensure this is set in Render
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; // ✅ Ensure this is set in Render

// ✅ Function to check if the input is a valid URL
function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// ✅ Function to fetch full page details using Puppeteer (Handles Cloudflare & JavaScript Rendering)
async function getWebsiteSummary(url) {
    console.log("🌍 Fetching website info for:", url);
    try {
const browser = await puppeteer.launch({
    executablePath: "/usr/bin/google-chrome-stable", // ✅ Use system Chrome
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
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

// ✅ Function to check URL in VirusTotal
async function checkVirusTotal(url) {
    console.log("🔍 Scanning URL with VirusTotal:", url);
    try {
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const data = await response.json();
        if (!data.data || !data.data.id) {
            return { error: "VirusTotal scan failed: Invalid response" };
        }

        const analysisId = data.data.id;
        await new Promise(resolve => setTimeout(resolve, 15000)); // ✅ Wait 15 seconds for VirusTotal to scan

        // ✅ Fetch VirusTotal scan report
        const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            method: "GET",
            headers: { "x-apikey": VIRUSTOTAL_API_KEY }
        });

        const reportData = await reportResponse.json();
        if (!reportData.data || !reportData.data.attributes) {
            return { error: "VirusTotal scan failed: No data" };
        }

        const stats = reportData.data.attributes.stats;
        return {
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            harmless: stats.harmless,
            undetected: stats.undetected
        };
    } catch (error) {
        console.error("❌ VirusTotal API Error:", error.message);
        return { error: "❌ Error scanning URL with VirusTotal" };
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

        const googleResponse = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestBody)
        });

        const googleData = await googleResponse.json();

        // ✅ Step 2: Get Website Summary (Now Uses Puppeteer)
        const websiteInfo = await getWebsiteSummary(url);

        // ✅ Step 3: Scan with VirusTotal
        const virusTotalData = await checkVirusTotal(url);

        let result = {
            originalURL: url,
            finalURL: websiteInfo.finalURL,
            title: websiteInfo.title,
            description: websiteInfo.description,
            virusTotal: virusTotalData
        };

        // ✅ Step 4: Return Safe or Threat Info
        if (googleData && googleData.matches && googleData.matches.length > 0) {
            result.safe = false;
            result.threats = googleData.matches.map(match => ({
                type: match.threatType,
                platform: match.platformType,
                url: match.threat.url
            }));
        } else {
            result.safe = true;
            result.message = "✅ No direct threats found!";
        }

        res.json(result);
    } catch (error) {
        res.status(500).json({ error: "❌ Internal Server Error" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
