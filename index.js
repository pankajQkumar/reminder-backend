const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const twilio = require("twilio");

// Load environment variables
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.error("Failed to connect to MongoDB:", err.message);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Twilio client setup
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Signup Route
app.post("/api/auth/signup", async (req, res) => {
  const { username, email, password, phone } = req.body;

  if (!username || !email || !password || !phone) {
    return res.status(400).json({ message: "All fields are required!" });
  }

  if (!/^\+[1-9]\d{1,14}$/.test(phone)) {
    return res.status(400).json({ message: "Invalid phone number format! Use +1234567890 format." });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters long!" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email is already in use!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      phone,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Error registering user", error: error.message });
  }
});

// Signin Route
app.post("/api/auth/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required!" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password!" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ message: "Login successful!", token, username: user.username });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

// Twilio Send SMS API
app.post("/api/send_sms", async (req, res) => {
  const { to, message } = req.body;

  if (!to || !message) {
    return res.status(400).json({ message: "Phone number and message are required!" });
  }

  if (!/^\+[1-9]\d{1,14}$/.test(to)) {
    return res.status(400).json({ message: "Invalid phone number format! Use +1234567890 format." });
  }

  try {
    const smsResponse = await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to,
    });

    res.status(200).json({ message: "SMS sent successfully!", sid: smsResponse.sid });
  } catch (error) {
    console.error("Error sending SMS:", error);
    res.status(500).json({
      message: "Failed to send SMS",
      error: error.message,
      code: error.code || "N/A",
      info: error.moreInfo || "No additional info",
    });
  }
});

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
