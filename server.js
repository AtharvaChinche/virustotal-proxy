const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const GOOGLE_API_KEY = process.env.API_KEY; // ✅ Ensure this is set

// ✅ Fix: Add a default route to check if the API is running
app.get("/", (req, res) => {
    res.send("✅ Google Safe Browsing API Proxy is running!");
});

app.post("/check-url", async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: "Missing URL in request body" });
    }

    try {
        console.log("📤 Checking URL with Google Safe Browsing:", url);

        const requestBody = {
            client: { clientId: "yourcompany", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
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

        if (data && data.matches && data.matches.length > 0) {
            res.json({ safe: false, threats: data.matches });
        } else {
            res.json({ safe: true, message: "✅ No threats found!" });
        }
    } catch (error) {
        console.error("❌ Google Safe Browsing API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`✅ Google Safe Browsing API Proxy running on port ${PORT}`));
