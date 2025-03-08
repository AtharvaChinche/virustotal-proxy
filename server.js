const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
app.use(express.json());

// ✅ Fix CORS: Allow Botpress requests
app.use(cors({
    origin: "*", // Allows all origins
    methods: "GET, POST",
    allowedHeaders: "Content-Type"
}));

const API_KEY = process.env.API_KEY; // ✅ Read from environment variable
app.get("/", (req, res) => {
    res.send("✅ VirusTotal API Proxy is running!");
});

app.post("/check-url", async (req, res) => {
    const url = req.body.url;
    
    if (!url) {
        return res.status(400).json({ error: "Missing URL" });
    }

    try {
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY, // ✅ Use the secure API Key
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
