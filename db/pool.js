const { Pool } = require("pg");
require("dotenv").config();

const isCloudDatabase = process.env.DATABASE_URL?.includes("neon.tech") || process.env.NODE_ENV === "production";

module.exports = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isCloudDatabase ? { rejectUnauthorized: false } : false,
});