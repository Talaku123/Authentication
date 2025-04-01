import express from "express"
import pg from "pg"
import { body, validationResult } from "express-validator"
import bcrypt from "bcrypt"
import env from "dotenv"

env.config(); // Load environment variables before using them

if (!process.env.DB_USER || !process.env.DB_HOST || !process.env.DB_NAME || !process.env.DB_PASSWORD || !process.env.DB_PORT) {
  console.error("Missing required environment variables. Please check your .env file.");
  process.exit(1); // Exit the application if environment variables are missing
}

const app = express()
const PORT = 3043


const db = new pg.Client(
{

    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: parseInt(process.env.DB_PORT, 10), // Ensure port is an integer
});


app.set("view engine", "ejs"); // Set EJS as the view engine


db.connect()
  .then(() => console.log("Postgres connected"))
  .catch((err) => console.error("Connection error", err.stack));
 

app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(express.static("public"))




app.get("/", (_, res) => {
    res.render("home.ejs")
})


app.get("/login", (_, res) => {
    res.render("login.ejs")
})

app.get("/register", (_, res) => {
    res.render("register.ejs")
})


app.post("/register",
[
  body("username").isEmail().withMessage("Invalid email"),
  body("password").isLength({min:8}).withMessage("Password must be at least 8 characters")
],

  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()})
    }

    const email = req.body.username
    const password = req.body.password
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

    try 
    {
      const checkResult = await db.query("SELECT * FROM users WHERE email=$1", [email]);

      if (checkResult.rows.length > 0) {
        res.send("Email Is Existed...");
      } else {
        await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashedPassword]);
        res.render("secrets.ejs"); // Ensure secrets.ejs exists in the views directory
      }

    } catch (err) {
      console.log(err)
      res.status(500).send("An error found")
    }
  }
)



app.post("/login", async (req, res) => {

  const email = req.body.username;
  const password = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.password;

      const isMatch = await bcrypt.compare(password, storedPassword); // Compare hashed password
      if (isMatch) {

        res.render("secrets.ejs");

      } else {
        res.send("You entered an incorrect password");
      }
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred");
  }
});



app.listen(PORT, () => {
    console.log(`Server is running at http://localhost${PORT}`)
})