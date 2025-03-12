const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 10000;
const GOOGLE_API_KEY = process.env.API_KEY; // ✅ Ensure this is set in Render

// ✅ Function to check if the input is a valid URL
function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// ✅ Default route to check if the API is running
app.get("/", (req, res) => {
    res.json({ message: "✅ Google Safe Browsing API is running!" });
});

// ✅ API to check if a URL is safe
app.post("/check-url", async (req, res) => {
    try {
        const { url } = req.body;

        if (!url || !isValidURL(url)) {
            return res.status(400).json({ error: "❌ Invalid request: Please enter a valid URL." });
        }

        console.log("📤 Checking URL:", url);

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

        // ✅ Return Safe or Threat Info
        if (data && data.matches && data.matches.length > 0) {
            res.json({
                safe: false,
                threats: data.matches.map(match => ({
                    type: match.threatType,
                    platform: match.platformType,
                    url: match.threat.url
                }))
            });
        } else {
            res.json({ safe: true, message: "✅ No threats found!" });
        }
    } catch (error) {
        console.error("❌ API Error:", error.message);
        res.status(500).json({ error: "❌ Internal Server Error" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
