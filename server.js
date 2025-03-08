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
                "
