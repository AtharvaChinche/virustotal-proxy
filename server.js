const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const { JSDOM } = require("jsdom"); // ✅ Extract website details
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

// ✅ Function to get website details & create a summary
async function getWebsiteSummary(url) {
    try {
        const response = await fetch(url, { redirect: "follow" });
        const finalURL = response.url;
        const html = await response.text();

        // ✅ Extract Title & Meta Description
        const dom = new JSDOM(html);
        const title = dom.window.document.querySelector("title")?.textContent || "No title found";
        const description = dom.window.document.querySelector("meta[name='description']")?.content || "No description available.";

        // ✅ Generate a short summary based on the website type
        let summary = `The website **${title}** (${finalURL}) appears to be about: ${description}`;

        // ✅ Add Risk Analysis
        if (title.toLowerCase().includes("torrent") || finalURL.includes("piratebay")) {
            summary += `\n\n⚠️ **Potential Risks:**\n- Torrent sites often distribute copyrighted content.\n- Some proxies may contain ads, trackers, or malware.\n- Accessing such sites might be restricted in some countries.`;
        } else if (title.toLowerCase().includes("bank") || description.toLowerCase().includes("login")) {
            summary += `\n\n⚠️ **Potential Risks:**\n- Be cautious of phishing attempts.\n- Do not enter personal information unless you verify it's an official site.`;
        }

        // ✅ Add Safety Measures
        summary += `\n\n🛡️ **Safety Measures:**\n- Always verify the URL before entering sensitive information.\n- Use a VPN for privacy on torrent or proxy sites.\n- Check the website in VirusTotal before visiting.`;

        return { finalURL, title, description, summary };
    } catch (error) {
        return { finalURL: url, title: "Error fetching site", description: "Could not analyze website", summary: "⚠️ Unable to retrieve website details." };
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

        // ✅ Step 2: Get Website Summary
        const websiteInfo = await getWebsiteSummary(url);

        let result = {
            originalURL: url,
            finalURL: websiteInfo.finalURL,
            title: websiteInfo.title,
            description: websiteInfo.description,
            summary: websiteInfo.summary
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
