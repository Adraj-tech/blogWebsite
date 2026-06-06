import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

// PostgreSQL Connection
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "users",
  password: "@Adarsh9771",
  port: 5432,
});

db.connect()
  .then(() => console.log("Connected to PostgreSQL"))
  .catch((err) => console.error("Database Connection Error:", err));

app.use(express.static("public"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set("view engine", "ejs");

app.use(session({
  secret: "blogwebsite",
  resave: false,
  saveUninitialized: false
}));

app.get("/", (req, res) => {

  res.render("index", {
    user: req.session.user
  });

});
app.get("/signup", (req, res) => {
  res.render("partials/signup");
});

app.get("/signin", (req, res) => {
  res.render("partials/signin");
});

app.get("/create", (req, res) => {
  res.render("partials/create");
});    

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "partials", "scienceDay.html"));
});
  
// Signup Page
app.get("/signup", (req, res) => {
  res.render("signup");
});


// Register User
app.post("/signup", async (req, res) => {

  const { name, email, password } = req.body;

  console.log("Received Data:", req.body);

  // Password Validation
  const passwordRegex =
    /^(?=.*[A-Z])(?=.*\d)(?=.*@).{6,}$/;

  if (!passwordRegex.test(password)) {

    return res.send(
      "Password must contain:<br><br>" +
      "• At least 6 characters<br>" +
      "• One uppercase letter<br>" +
      "• One number<br>" +
      "• One @ symbol"
    );

  }

  try {

    // Check if email already exists
    const existingUser = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {

      return res.send(
        "Email already registered!"
      );

    }

    // Hash password
    const hashedPassword =
      await bcrypt.hash(password, 10);

    // Insert user
    await db.query(

      `INSERT INTO users
      (name, email, password)
      VALUES ($1, $2, $3)`,

      [name, email, hashedPassword]

    );

    res.send(
      "User registered successfully!"
    );

  } catch (err) {

    console.error(
      "Registration Error:",
      err
    );

    res.status(500).send(
      err.message
    );

  }

});


// SIGN IN
 app.post("/signin", async (req, res) => {

  const { email, password } = req.body;

  try {

    const result = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.send("User not found!");
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (isMatch) {

      req.session.user = user;

      res.redirect("/");

    } else {

      res.send("Incorrect Password");

    }

  } catch (err) {

    console.log(err);
    res.send("Server Error");

  }

});
//BLOG
app.get("/blog", (req, res) => {

  if(!req.session.user){
    return res.redirect("/signin");
  }

  res.render("blog");

});

app.post("/blog", async (req, res) => {

  if(!req.session.user){
    return res.redirect("/signin");
  }

  const { title, content } = req.body;

  const user = req.session.user;

  await db.query(
    `INSERT INTO blogs
    (title, content, author_email, author_name)
    VALUES($1,$2,$3,$4)`,

    [
      title,
      content,
      user.email,
      user.name
    ]
  );

  res.redirect("/blogs");

});

// PUBLIC BLOG
app.get("/blogs", async (req, res) => {

  try {

    const result = await db.query(
      "SELECT * FROM blogs ORDER BY created_at DESC"
    );

    res.render("partials/blogs", {
      blogs: result.rows
    });

  } catch (err) {

    console.log(err);
    res.send("Error Loading Blogs");

  }

});

// VIEW

app.get("/blogs/:title", async (req, res) => {

  const title = req.params.title;

  try {

    const result = await db.query(
      "SELECT * FROM blogs WHERE title = $1",
      [title]
    );

    res.render("partials/blogs", {
      blogs: result.rows,
      user: req.session.user
    });

  } catch (err) {

    console.log(err);

    res.send("Error Loading Blogs");

  }

});

// LOGOUT

app.get("/logout", (req, res) => {

  req.session.destroy((err) => {

    if(err){
      console.log(err);
      return res.send("Error Logging Out");
    }

    res.redirect("/");

  });

});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});