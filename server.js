const express = require("express");
const app = express();
const bcrypt = require("bcryptjs");
const mysql = require("mysql2");
require("dotenv").config();

const port = process.env.PORT || 3000;

app.use(express.json());



const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL connected");
});


app.post("/register", (req, res) => {
  const { username, password } = req.body;

  
  const checkUserSql = `SELECT * FROM users WHERE username = ?`;
  db.query(checkUserSql, [username], (err, result) => {
    if (err) return res.status(500).json({ message: "Error checking user" });

    if (result.length > 0) {
      return res.status(400).json({ message: "Username already exists" });
    }

  
    const hashedPassword = bcrypt.hashSync(password, 10);

 
    const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.query(sql, [username, hashedPassword], (err, result) => {
      if (err)
        return res.status(500).json({ message: "Error registering user" });
      res.status(201).json({ message: "User registered successfully" });
    });
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql = `SELECT * FROM users WHERE username = ?`;
  db.query(sql, [username], (err, result) => {
    if (err) return res.status(500).json({ message: "Error during login" });

    if (result.length === 0) {
      console.log("User not found");
      return res.status(400).json({ message: "Invalid username or password" });
    }

    const user = result[0];
   

    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid) {
      console.log("Invalid password");
      return res.status(400).json({ message: "Invalid username or password" });
    }

    res.status(200).json({ message: "Login successful" });
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
