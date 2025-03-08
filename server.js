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

        // Step 2: Fetch the scan report
        const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            method: "GET",
            headers: {
                "x-apikey": process.env.API_KEY
            }
        });

        const reportData = await reportResponse.json();
        res.json(reportData); // ✅ Return full scan report

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
