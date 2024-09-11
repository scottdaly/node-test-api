const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");
const db = require("./db"); // Import the database connection

const app = express();
const port = 3000;
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cookieParser = require("cookie-parser");

require("dotenv").config();

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:5173", // Vite's default port
  credentials: true, // This is important for cookies
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
// Middleware to parse JSON bodies
app.use(bodyParser.json());

app.use(cookieParser());

// Initialize passport
app.use(passport.initialize());

// JWT helper functions
const createToken = (user) => {
  return jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

const createRefreshToken = (user) => {
  return jwt.sign({ userId: user.id }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
};

/* Google Login */

// Set up Passport Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // First, try to find an existing user
        let result = await dbquery(
          "SELECT id, username, name, email, google_id, created_at, oauth_provider, last_login FROM users WHERE google_id = $1",
          [profile.id]
        );

        let user;

        if (result.rows.length > 0) {
          // User exists, update their information
          user = result.rows[0];
          await pool.query(
            "UPDATE users SET email = $1, name = $2, last_login = NOW() WHERE google_id = $3",
            [profile.emails[0].value, profile.displayName, profile.id]
          );
        } else {
          // User doesn't exist, create a new one
          result = await db.query(
            `INSERT INTO users (google_id, email, name, username, oauth_provider, created_at, last_login)
         VALUES ($1, $2, $3, $4, 'google', NOW(), NOW())
         RETURNING id, username, name, email, google_id, created_at, oauth_provider, last_login`,
            [
              profile.id,
              profile.emails[0].value,
              profile.displayName,
              profile.emails[0].value,
            ]
          );
          user = result.rows[0];
        }

        done(null, user);
      } catch (error) {
        console.error("Error in Google Strategy:", error);
        done(error, null);
      }
    }
  )
);

// Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    const user = req.user;
    const token = createToken(user);
    const refreshToken = createRefreshToken(user);

    await db.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [
      refreshToken,
      user.id,
    ]);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.redirect("http://localhost:5173/");
  }
);

// Local registration route
app.post("/auth/register", async (req, res) => {
  const { username, email, password, name } = req.body;
  try {
    const hashedPassword = await argon2.hash(password);
    const result = await db.query(
      `INSERT INTO users (username, email, password, name, oauth_provider, created_at, last_login)
       VALUES ($1, $2, $3, $4, 'local', NOW(), NOW())
       RETURNING id, username, email, name`,
      [username, email, hashedPassword, name]
    );
    const user = result.rows[0];
    const token = createToken(user);
    const refreshToken = createRefreshToken(user);

    await db.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [
      refreshToken,
      user.id,
    ]);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// Local login route
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query(
      "SELECT * FROM users WHERE email = $1 AND oauth_provider = 'local'",
      [email]
    );
    const user = result.rows[0];

    if (
      !user ||
      !user.password ||
      !(await argon2.verify(user.password, password))
    ) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = createToken(user);
    const refreshToken = createRefreshToken(user);

    await db.query(
      "UPDATE users SET refresh_token = $1, last_login = NOW() WHERE id = $2",
      [refreshToken, user.id]
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.json({
      message: "Logged in successfully",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Access denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ error: "Token expired", shouldRefresh: true });
    }
    res.status(400).json({ error: "Invalid token" });
  }
};

// Token refresh route
app.post("/auth/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken)
    return res.status(401).json({ error: "Refresh token not found" });

  try {
    const verified = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const result = await db.query(
      "SELECT * FROM users WHERE id = $1 AND refresh_token = $2",
      [verified.userId, refreshToken]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    const user = result.rows[0];
    const newToken = createToken(user);
    const newRefreshToken = createRefreshToken(user);

    await db.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [
      newRefreshToken,
      user.id,
    ]);

    res.cookie("token", newToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });
    res.json({ message: "Token refreshed successfully" });
  } catch (err) {
    res.status(400).json({ error: "Invalid refresh token" });
  }
});

// Protected route example
app.get("/api/protected", verifyToken, (req, res) => {
  res.json({ message: "This is a protected route", userId: req.user.userId });
});

// Logout route
app.get("/auth/logout", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    await db.query(
      "UPDATE users SET refresh_token = NULL WHERE refresh_token = $1",
      [refreshToken]
    );
  }
  res.clearCookie("token");
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
});

// User info route
app.get("/api/user", verifyToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, username, email, name, oauth_provider FROM users WHERE id = $1",
      [req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Error fetching user data" });
  }
});

/* User Routes */

// List all users
app.get("/users", async (req, res) => {
  console.log("getting users");
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
  console.log("posting to users");
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
      [username, name, email, password]
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
  console.log("patching to users");
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
  console.log("deleting user");
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
  console.log("getting characters");
  try {
    const result = await db.query("SELECT * FROM characters");
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Get a specific character by ID
app.get("/characters/:id", async (req, res) => {
  const { id } = req.params;
  console.log("getting character");

  try {
    // Query to fetch the character by ID
    const result = await db.query("SELECT * FROM characters WHERE id = $1", [
      id,
    ]);

    // If no character was found, return a 404
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Character not found" });
    }

    // Return the character details
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Create a new character
app.post("/characters", async (req, res) => {
  console.log("creating character");
  const { name, description, image_url, model, creator_id } = req.body;

  if (!name || !description) {
    return res
      .status(400)
      .json({ message: "Name and description are required" });
  }

  if (!model) {
    return res.status(400).json({ message: "Model is required" });
  }

  if (!creator_id) {
    return res
      .status(400)
      .json({ message: "Creator's creator_id is required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO characters (name, description, image_url, model, creator_id) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, description, image_url || null, model, creator_id]
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
  const { name, description, image_url, model } = req.body;
  console.log("patching character");

  // Build the dynamic SQL query based on the provided fields
  const updates = [];
  if (name) updates.push(`name = '${name}'`);
  if (description) updates.push(`description = '${description}'`);
  if (image_url !== undefined) updates.push(`image_url = '${image_url}'`);
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
    )}, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *`;
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
  console.log("deleting character");

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
  const { user_id, character_id } = req.query;
  console.log("getting conversations");

  if (!user_id) {
    return res.status(400).json({ message: "user_id is required" });
  }

  try {
    let result;

    if (character_id) {
      // If character_id is provided, filter by both user_id and character_id
      result = await db.query(
        `SELECT * FROM conversations 
         WHERE user_id = $1 AND character_id = $2 
         ORDER BY last_message_at DESC`,
        [user_id, character_id]
      );
    } else {
      // If only user_id is provided, fetch all conversations for that user
      result = await db.query(
        `SELECT * FROM conversations 
         WHERE user_id = $1 
         ORDER BY last_message_at DESC`,
        [user_id]
      );
    }

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error" });
  }
});

// Get a specific conversation by ID
app.get("/conversations/:id", async (req, res) => {
  const { id } = req.params;
  console.log("getting conversation");

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
  console.log("creating conversation");

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
  console.log("patching conversation");

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
  console.log("deleting conversation");

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
  console.log("getting messages");

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
  console.log("posting message");

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
  console.log("deleting message");

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

app.post("/chat", async (req, res) => {
  const { conversation_id } = req.body;

  try {
    const messages = await db.query(
      "SELECT * FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC",
      [conversation_id]
    );

    const conversationContext = messages.rows.map((msg) => ({
      role: msg.role,
      content: msg.content,
    }));

    const llmResponse = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o", // Or whichever LLM model you're using
        messages: conversationContext,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Got llm response", llmResponse.data.choices[0].message);

    const aiMessage = llmResponse.data.choices[0].message.content;
    const aiRole = llmResponse.data.choices[0].message.role;

    await db.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, $2, $3)",
      [conversation_id, aiRole, aiMessage]
    );

    res.json({
      ai_message: aiMessage,
      conversation_id: conversation_id,
    });
  } catch (err) {
    console.log("Error with chat route", err);
    res
      .send(500)
      .json({ message: "Failed to generate AI response", error: err });
  }
});

app.post("/get-title", async (req, res) => {
  const { conversation_id } = req.body;
  console.log("Generating Title for conversation id", conversation_id);

  try {
    const messages = await db.query(
      "SELECT * FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC",
      [conversation_id]
    );

    if (messages.length === 0) {
      return res
        .status(404)
        .json({ message: "No messages found for the conversation" });
    }

    const conversationContext = messages.rows.map((msg) => ({
      role: msg.role,
      content: msg.content,
    }));

    let conversationString = JSON.stringify(conversationContext);

    console.log("conversation context", conversationString);

    const llmResponse = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o-mini", // Or whichever LLM model you're using
        messages: [
          {
            role: "system",
            content:
              'Your job is to write a brief, descriptive title for the following conversation. Return just your title between two <title></title> tags. Here is an example: {"role":"user", "content":"Write a short poem about traffic lights"}, {"role":"assistant", "content":"Traffic lights upon the street, Colors bright where roads all meet. Red for stop, green for go, Yellow warns to take it slow. They guide our paths with steady gleam, A simple dance, a daily theme. In their glow, we pause and start, Silent keepers of the city\'s heart.}" Your response: "<title>Traffic Lights Poem</title>"',
          },
          {
            role: "user",
            content: `Write a title for the following conversation: ${JSON.stringify(
              conversationString
            )}`,
          },
        ],
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Got llm response", llmResponse.data.choices[0].message);

    function extractTitle(htmlString) {
      const titleMatch = htmlString.match(/<title>(.*?)<\/title>/);
      return titleMatch ? titleMatch[1] : null;
    }

    const generatedTitle = extractTitle(
      llmResponse.data.choices[0].message.content
    );

    await db.query("UPDATE conversations SET title = $1 WHERE id = $2", [
      generatedTitle,
      conversation_id,
    ]);

    res.json({
      conversation_id,
      title: generatedTitle,
    });
  } catch (err) {
    console.log("Error with chat route", err);
    res
      .send(500)
      .json({ message: "Failed to generate AI response", error: err });
  }
});

app.listen(port, () => {
  console.log(`postgres port is ${process.env.POSTGRES_PORT}`);
  console.log(`Server running on http://localhost:${port}`);
});
