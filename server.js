const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 10000; // ✅ Use Render's assigned port

// ✅ Default route to check if the API is running
app.get("/", (req, res) => {
    res.send("✅ Google Safe Browsing API is running!");
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
