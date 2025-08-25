const pool = require("../db/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

exports.createCompanyAdmin = async (req, res) => {
  let connection;
  const { username, companyName, password } = req.body;

  try {
    if (!username || !companyName || !password || !req.file) {
      return res.status(400).json({
        message: "All fields are required to create the company admin account",
      });
    }

    connection = await pool.getConnection();

    // Check if email already exists
    const [user] = await connection.query(
      "SELECT username FROM users WHERE username = ? AND role_id = ?",
      [username, 7] 
    );

    if (user.length !== 0) {
      return res.status(409).json({
        message: "Company Admin already exists",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

     // Save file path (from multer)
    const filePath = req.file.path;

    // Insert into users table
    const [result] = await connection.query(
      "INSERT INTO users (username, company, password, role_id,logo) VALUES (?, ?, ?, ?,?)",
      [username, companyName, hashedPassword, 7,filePath]
    );

    // Generate JWT token (optional)
    // const token = jwt.sign(
    //   { id: result.insertId, email, role: "company_admin" },
    //   process.env.JWT_SECRET || "secretkey",
    //   { expiresIn: "1h" }
    // );

    return res.status(201).json({
      message: "Company Admin account created successfully",
      userId: result.insertId,
      
    });

  } catch (error) {
    console.error("Error creating company admin:", error);
    return res.status(500).json({
      message: "Internal server error",
      error: error.message,
    });
  } finally {
    if (connection) connection.release();
  }
};

