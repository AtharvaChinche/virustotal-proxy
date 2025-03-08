const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");

// ✅ Fix: Initialize Express before using "app"
const app = express();

app.use(express.json());

// ✅ Fix CORS issue
app.use(cors({
    origin: "*",
    methods: "GET, POST",
    allowedHeaders: "Content-Type"
}));

// ✅ Test Route for Browser
app.get("/", (req, res) => {
    res.send("✅ VirusTotal API Proxy is running!");
});

// ✅ VirusTotal API Proxy Route
app.post("/check-url", async (req, res) => {
    const url = req.body.url;

    if (!url) {
        return res.status(400).json({ error: "Missing URL" });
    }

    try {
        // Step 1: Submit URL for analysis
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": process.env.API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const data = await response.json();
        const analysisId = data.data.id;

        // ✅ Step 2: Wait 15 seconds before fetching the report (to allow VirusTotal to scan)
        await new Promise(resolve => setTimeout(resolve, 15000)); // 15-second delay

        // Step 3: Fetch the scan report
        const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            method: "GET",
            headers: {
                "x-apikey": process.env.API_KEY
            }
        });

        const reportData = await reportResponse.json();
        res.json(reportData);

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ Fix: Ensure Express app listens at the end
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
