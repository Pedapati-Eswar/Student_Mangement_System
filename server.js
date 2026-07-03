const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const DATA_FILE = path.join(__dirname, "data", "students.json");
const SECRET = "sms_secret_2024";

function readData() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE)); } catch { return []; }
}
function writeData(d) { fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2)); }

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ message: "Invalid token" }); }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
    next();
  });
}

// Register
app.post("/register", async (req, res) => {
  const { username, password, fullName, email, course, mobile, gender, dob, address } = req.body;
  if (!username || !password || !fullName || !email || !course || !mobile || !gender || !dob)
    return res.status(400).json({ message: "All fields required" });

  let students = readData();
  if (students.find(s => s.username === username || s.email === email))
    return res.status(400).json({ message: "Username or email already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const student = {
    id: Date.now().toString(),
    username, password: hashed, fullName, email,
    course, mobile, gender, dob, address: address || "",
    role: "student", enrolledDate: new Date().toISOString().split("T")[0],
    grades: [], attendance: [], cgpa: 0
  };
  students.push(student);
  writeData(students);
  res.json({ message: "Registered successfully" });
});

// Student Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const students = readData();
  const user = students.find(s => s.username === username && s.role === "student");
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, username: user.username, role: "student" }, SECRET, { expiresIn: "8h" });
  const { password: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

// Admin Login
app.post("/admin-login", async (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "admin123") {
    const token = jwt.sign({ username: "admin", role: "admin" }, SECRET, { expiresIn: "8h" });
    return res.json({ token });
  }
  res.status(401).json({ message: "Invalid admin credentials" });
});

// Get own profile
app.get("/profile", auth, (req, res) => {
  const students = readData();
  const user = students.find(s => s.id === req.user.id);
  if (!user) return res.status(404).json({ message: "Not found" });
  const { password: _, ...safeUser } = user;
  res.json(safeUser);
});

// Update own profile
app.put("/profile", auth, async (req, res) => {
  let students = readData();
  const idx = students.findIndex(s => s.id === req.user.id);
  if (idx === -1) return res.status(404).json({ message: "Not found" });
  const { password, role, id, grades, attendance, cgpa, ...allowed } = req.body;
  if (password) allowed.password = await bcrypt.hash(password, 10);
  students[idx] = { ...students[idx], ...allowed };
  writeData(students);
  res.json({ message: "Profile updated" });
});

// Get all students (admin)
app.get("/students", adminAuth, (req, res) => {
  const { search, course, gender } = req.query;
  let students = readData().filter(s => s.role === "student");
  if (search) students = students.filter(s =>
    s.username.toLowerCase().includes(search.toLowerCase()) ||
    s.fullName.toLowerCase().includes(search.toLowerCase()) ||
    s.email.toLowerCase().includes(search.toLowerCase())
  );
  if (course) students = students.filter(s => s.course === course);
  if (gender) students = students.filter(s => s.gender === gender);
  res.json(students.map(({ password: _, ...s }) => s));
});

// Get single student (admin)
app.get("/students/:id", adminAuth, (req, res) => {
  const student = readData().find(s => s.id === req.params.id);
  if (!student) return res.status(404).json({ message: "Not found" });
  const { password: _, ...safeStudent } = student;
  res.json(safeStudent);
});

// Update student (admin)
app.put("/students/:id", adminAuth, async (req, res) => {
  let students = readData();
  const idx = students.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: "Not found" });
  const { password, id, ...updates } = req.body;
  if (password) updates.password = await bcrypt.hash(password, 10);
  students[idx] = { ...students[idx], ...updates };
  writeData(students);
  res.json({ message: "Updated" });
});

// Delete student (admin)
app.delete("/students/:id", adminAuth, (req, res) => {
  let students = readData();
  students = students.filter(s => s.id !== req.params.id);
  writeData(students);
  res.json({ message: "Deleted" });
});

// Add grade (admin)
app.post("/students/:id/grades", adminAuth, (req, res) => {
  let students = readData();
  const idx = students.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: "Not found" });
  const { subject, marks, maxMarks, semester } = req.body;
  if (!subject || marks === undefined || !maxMarks || !semester)
    return res.status(400).json({ message: "All grade fields required" });
  students[idx].grades.push({ subject, marks, maxMarks, semester, date: new Date().toISOString().split("T")[0] });
  // Recalculate CGPA
  const grades = students[idx].grades;
  students[idx].cgpa = grades.length
    ? (grades.reduce((sum, g) => sum + (g.marks / g.maxMarks) * 10, 0) / grades.length).toFixed(2)
    : 0;
  writeData(students);
  res.json({ message: "Grade added" });
});

// Mark attendance (admin)
app.post("/students/:id/attendance", adminAuth, (req, res) => {
  let students = readData();
  const idx = students.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: "Not found" });
  const { date, status, subject } = req.body;
  if (!date || !status || !subject) return res.status(400).json({ message: "All fields required" });
  students[idx].attendance.push({ date, status, subject });
  writeData(students);
  res.json({ message: "Attendance marked" });
});

// Stats (admin)
app.get("/stats", adminAuth, (req, res) => {
  const students = readData().filter(s => s.role === "student");
  const courses = {};
  students.forEach(s => { courses[s.course] = (courses[s.course] || 0) + 1; });
  res.json({
    total: students.length,
    courses,
    avgCgpa: students.length
      ? (students.reduce((sum, s) => sum + parseFloat(s.cgpa || 0), 0) / students.length).toFixed(2)
      : 0
  });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
