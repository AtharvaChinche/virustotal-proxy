const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const { JSDOM } = require("jsdom"); // ✅ To extract website content
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const GOOGLE_API_KEY = process.env.API_KEY; // ✅ Ensure this is set

// ✅ Function to check if the input is a valid URL
function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// ✅ Function to fetch final redirected URL & page contents
async function getWebsiteInfo(url) {
    try {
        const response = await fetch(url, { redirect: "follow" }); // ✅ Follow Redirects
        const finalURL = response.url; // ✅ Get final destination URL
        const html = await response.text(); // ✅ Get page HTML

        // ✅ Extract Title & Meta Description
        const dom = new JSDOM(html);
        const title = dom.window.document.querySelector("title")?.textContent || "No title found";
        const description = dom.window.document.querySelector("meta[name='description']")?.content || "No description found";

        return { finalURL, title, description };
    } catch (error) {
        console.error("❌ Error fetching website info:", error.message);
        return { finalURL: url, title: "Error fetching site", description: "Error fetching details" };
    }
}

// ✅ Default route to check if the API is running
app.get("/", (req, res) => {
    res.send("✅ Google Safe Browsing API Proxy with Redirect & Content Analysis is running!");
});

app.post("/check-url", async (req, res) => {
    const { url } = req.body;

    // ✅ Step 1: Check if the URL is valid
    if (!url || !isValidURL(url)) {
        return res.status(400).json({ error: "❌ Invalid URL. Please enter a valid website link." });
    }

    try {
        console.log("📤 Checking URL with Google Safe Browsing:", url);

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
        console.log("🔍 Google Safe Browsing Response:", JSON.stringify(data, null, 2));

        // ✅ Step 2: Fetch Redirects & Website Content
        const websiteInfo = await getWebsiteInfo(url);

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
        console.error("❌ Google Safe Browsing API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Google Safe Browsing API with Redirect Analysis running on port ${PORT}`));
