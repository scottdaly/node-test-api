const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const db = require("./db"); // Import the database connection
const app = express();
const port = 3000;
require("dotenv").config();

app.use(cors());
// Middleware to parse JSON bodies
app.use(bodyParser.json());

/* User Routes */

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

// Create a new user
app.post("/users", async (req, res) => {
  const { username, name, email, password } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO users (username, name, email, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, name, email, hashedPassword]
    );

    // Return the created user (excluding the password)
    const { password: _, ...user } = result.rows[0];

    res.status(201).json({ message: "User created!", user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Update a user's details
app.patch("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { username, name, email, password } = req.body;

  // Build the dynamic SQL query based on the provided fields
  const updates = [];
  if (username) updates.push(`username = '${username}'`);
  if (name) updates.push(`name = '${name}'`);
  if (email) updates.push(`email = '${email}'`);
  if (password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    updates.push(`password = '${hashedPassword}'`);
  }

  if (updates.length === 0) {
    return res
      .status(400)
      .json({ message: "No valid fields provided for update" });
  }

  try {
    const query = `UPDATE users SET ${updates.join(
      ", "
    )} WHERE id = $1 RETURNING *`;
    const result = await db.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const { password: _, ...user } = result.rows[0]; // Exclude password from response
    res.json({ message: "User updated!", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Delete a user
app.delete("/users/:id", async (req, res) => {
  const { id } = req.params;

  try {
    // Run the SQL query to delete the user
    const result = await db.query(
      "DELETE FROM users WHERE id = $1 RETURNING *",
      [id]
    );

    // If no user was found, return 404
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // Return a success message
    res.json({ message: "User deleted", user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

/* Character Routes */

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

app.patch("/characters/:id", async (req, res) => {
  const { id } = req.params;
  const { name, description, model } = req.body;

  // Build the dynamic SQL query based on the provided fields
  const updates = [];
  if (name) updates.push(`name = '${name}'`);
  if (description) updates.push(`description = '${description}'`);
  if (model) updates.push(`model = '${model}'`);

  if (updates.length == 0) {
    return res
      .status(400)
      .json({ message: "No valid fields provided for update" });
  }

  try {
    // Construct SQL query dynamically
    const query = `UPDATE characters SET ${updates.join(
      ", "
    )} WHERE id = $1 RETURNING *`;
    const result = await db.query(query, [id]);

    // If no character was found, return 404
    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "No character found with that id" });
    }

    res.json({ message: "Character updated!", character: result.rows[0] });
  } catch (err) {
    console.log("Error", err);
    return res.status(500).json({ message: `Database error: ${err}` });
  }
});

app.delete("/characters/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      "DELETE FROM characters WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No character found" });
    }

    res.json({ message: "Character deleted", character: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Database error: ${err}` });
  }
});

/* Conversation Routes */

// Get all conversations for a user
app.get("/conversations", async (req, res) => {
  const { user_id } = req.query;

  if (!user_id) {
    return res.status(400).json({ message: "user_id is required" });
  }

  try {
    const result = await db.query(
      "SELECT * FROM conversations WHERE user_id = $1 ORDER BY last_message_at DESC",
      [user_id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Get a specific conversation by ID
app.get("/conversations/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query("SELECT * FROM conversations WHERE id = $1", [
      id,
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Conversation not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Create a new conversation
app.post("/conversations", async (req, res) => {
  const { user_id, character_id, title } = req.body;

  if (!user_id || !character_id || !title) {
    return res
      .status(400)
      .json({ message: "user_id, character_id, and title are required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO conversations (user_id, character_id, title) VALUES ($1, $2, $3) RETURNING *",
      [user_id, character_id, title]
    );

    res
      .status(201)
      .json({ message: "Conversation created!", conversation: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Update a conversation's details
app.patch("/conversations/:id", async (req, res) => {
  const { id } = req.params; // The conversation ID from the URL
  const { title, last_message_content, last_message_role } = req.body;

  // Build the dynamic SQL query based on the provided fields
  const updates = [];
  if (title) updates.push(`title = '${title}'`);
  if (last_message_content)
    updates.push(`last_message_content = '${last_message_content}'`);
  if (last_message_role)
    updates.push(`last_message_role = '${last_message_role}'`);

  // If no valid fields are provided, return a 400 Bad Request
  if (updates.length === 0) {
    return res
      .status(400)
      .json({ message: "No valid fields provided for update" });
  }

  try {
    // Construct the SQL query dynamically
    const query = `UPDATE conversations SET ${updates.join(
      ", "
    )} WHERE id = $1 RETURNING *`;
    const result = await db.query(query, [id]);

    // If no conversation was found, return a 404
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Conversation not found" });
    }

    // Return the updated conversation
    res.json({
      message: "Conversation updated!",
      conversation: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Delete a conversation by ID
app.delete("/conversations/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      "DELETE FROM conversations WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Conversation not found" });
    }

    res.json({ message: "Conversation deleted", conversation: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

/* Message routes */

// Get all messages for a conversation
app.get("/messages", async (req, res) => {
  const { conversation_id } = req.query;

  if (!conversation_id) {
    return res.status(400).json({ message: "conversation_id is required" });
  }

  try {
    const result = await db.query(
      "SELECT * FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC",
      [conversation_id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Add a message to a conversation
app.post("/messages", async (req, res) => {
  const { conversation_id, role, content } = req.body;

  if (!conversation_id || !role || !content) {
    return res
      .status(400)
      .json({ message: "conversation_id, role, and content are required" });
  }

  try {
    // Insert the message
    const messageResult = await db.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, $2, $3) RETURNING *",
      [conversation_id, role, content]
    );

    // Update the conversation's message count and last message
    await db.query(
      `UPDATE conversations 
         SET message_count = message_count + 1, 
             last_message_content = $1, 
             last_message_role = $2, 
             last_message_at = CURRENT_TIMESTAMP 
         WHERE id = $3`,
      [content, role, conversation_id]
    );

    res
      .status(201)
      .json({ message: "Message added!", message: messageResult.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Delete a message by ID
app.delete("/messages/:id", async (req, res) => {
  const { id } = req.params;

  try {
    // Retrieve the message to get its conversation_id before deleting
    const messageResult = await db.query(
      "SELECT * FROM messages WHERE id = $1",
      [id]
    );

    if (messageResult.rows.length === 0) {
      return res.status(404).json({ message: "Message not found" });
    }

    const { conversation_id, created_at } = messageResult.rows[0];

    // Delete the message
    await db.query("DELETE FROM messages WHERE id = $1", [id]);

    // Decrement the message count in the conversation
    await db.query(
      `UPDATE conversations 
         SET message_count = message_count - 1 
         WHERE id = $1`,
      [conversation_id]
    );

    // Check if the deleted message was the last one in the conversation
    const lastMessageResult = await db.query(
      `SELECT content, role, created_at 
         FROM messages 
         WHERE conversation_id = $1 
         ORDER BY created_at DESC 
         LIMIT 1`,
      [conversation_id]
    );

    if (lastMessageResult.rows.length > 0) {
      // There is still a message in the conversation, so update last_message_* fields
      const {
        content,
        role,
        created_at: lastCreatedAt,
      } = lastMessageResult.rows[0];
      await db.query(
        `UPDATE conversations 
           SET last_message_content = $1, last_message_role = $2, last_message_at = $3 
           WHERE id = $4`,
        [content, role, lastCreatedAt, conversation_id]
      );
    } else {
      // No more messages in the conversation, reset last_message_* fields
      await db.query(
        `UPDATE conversations 
           SET last_message_content = NULL, last_message_role = NULL, last_message_at = NULL 
           WHERE id = $1`,
        [conversation_id]
      );
    }

    res.json({ message: "Message deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

app.listen(port, () => {
  console.log(`postgres port is ${process.env.POSTGRES_PORT}`);
  console.log(`Server running on http://localhost:${port}`);
});
