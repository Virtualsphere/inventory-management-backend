const mysql = require('mysql2');
const dotenv = require('dotenv');

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
})

const testConnection = async () => {
  try {
    const [rows] = await pool.promise().query("SELECT NOW()")
    console.log("Database connected:", rows[0]["NOW()"])
  } catch (error) {
    console.error("Database connection failed:", error)
    process.exit(1) // Exit the application with an error
  }
}

testConnection()
module.exports = pool.promise()