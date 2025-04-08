require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/User")

const app = express();
app.use(express.json());
app.use(cors());
const PORT = 4400;

const activeUsers = new Set();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error("MongoDB Connection Error:", err));




  app.post("/login", async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
  
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ error: "User not found" });
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });
  
      if (activeUsers.has(user.email)) {
        return res.status(403).json({ error: "User already logged in" });
      }
  
      activeUsers.add(user.email); // Mark user as logged in
  
      const token = jwt.sign({ id: user._id, fullName: user.fullName }, "your_secret_key", { expiresIn: "1h" });
  
      res.json({ message: "Login successful", token, fullName: user.fullName });
    } catch (err) {
      res.status(500).json({ error: "Server error" });
    }
  });

  app.post("/register", async (req, res) => {
    const { fullName, email, password } = req.body;
  
    // 1. Validate input
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
  
    try {
      // 2. Check if user exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ error: "Email already registered" });
      }
  
      // 3. Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // 4. Create and save user
      const newUser = new User({
        fullName,
        email,
        password: hashedPassword,
      });
  
      await newUser.save();
  
      res.status(201).json({ message: "Registration successful" });
    } catch (err) {
      console.error("Register Error:", err);
      res.status(500).json({ error: "Server error" });
    }
  });
  
  
  app.post("/logout", (req, res) => {
    const { email } = req.body;
    activeUsers.delete(email);
    res.json({ message: "Logout successful" });
  });

app.get("/",(req,res)=>{
  res.send("your smart home application into online")
})
  
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));