const express = require("express");
const bodyParser = require("body-parser");
const db = require("./db"); // Import the database connection
const app = express();
const port = 3000;
require("dotenv").config();

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Create a new user
app.post("/users", async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO users (username) VALUES ($1) RETURNING *",
      [username]
    );
    res.status(201).json({ message: "User created!", user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// List all users
app.get("/users", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM users");
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Create a new character
app.post("/characters", async (req, res) => {
  const { name, description, model, userID } = req.body;

  if (!name || !description) {
    return res
      .status(400)
      .json({ message: "Name and description are required" });
  }

  if (!model) {
    return res.status(400).json({ message: "Model is required" });
  }

  if (!userID) {
    return res.status(400).json({ message: "Creator's userID is required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO characters (name, description, model, userID) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, description, model, userID]
    );
    res
      .status(201)
      .json({ message: "Character created!", character: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// List all characters
app.get("/characters", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM characters");
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

app.listen(port, () => {
  console.log(`postgres port is ${process.env.POSTGRES_PORT}`);
  console.log(`Server running on http://localhost:${port}`);
});
