const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors()); // Allow CORS

const API_KEY = "df02032ba4027f7b37a5e598f63a8e18ad927c30089543bd15879e6477c5b833"; // 🔹 Replace with your actual API key

app.post("/check-url", async (req, res) => {
    const url = req.body.url;
    
    if (!url) {
        return res.status(400).json({ error: "Missing URL" });
    }

    try {
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY,
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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
