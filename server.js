const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());
app.get("/", (req, res) => {
    res.send("✅ VirusTotal API Proxy is running!");
});

const VIRUSTOTAL_API_KEY = process.env.API_KEY; // ✅ Make sure this is set

app.post("/check-url", async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: "Missing URL" });
    }

    try {
        // ✅ Step 1: Submit URL for analysis
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const data = await response.json();

        if (!data || !data.data || !data.data.id) {
            throw new Error("Invalid VirusTotal response: Missing 'id'");
        }

        const analysisId = data.data.id;

        // ✅ Step 2: Wait before fetching the report
        await new Promise(resolve => setTimeout(resolve, 15000)); // 15-second delay

        // ✅ Step 3: Fetch the scan report
        const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            method: "GET",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
        });

        const reportData = await reportResponse.json();

        if (!reportData || !reportData.data) {
            throw new Error("Invalid VirusTotal response: Missing 'data'");
        }

        res.json(reportData);

    } catch (error) {
        console.error("❌ VirusTotal API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ VirusTotal API Proxy running on port ${PORT}`));
