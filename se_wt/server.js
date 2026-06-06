/**
 * ══════════════════════════════════════════════════════
 *  SplitSmart — Backend Server  (server.js)
 *  Node.js + Express + MongoDB (Mongoose) + JWT
 *
 *  CHANGES in v4:
 *    • Multiple groups — each expense/member/payment belongs to a groupId
 *    • Viewer accounts — can read data but cannot create/delete
 *    • Delete single expense  DELETE /api/expenses/:id
 *    • Custom payer amounts stored in expense (payerAmounts map)
 *    • Custom split amounts stored in expense (splitAmounts map)
 *    • Password validation — 8 chars, 1 uppercase, 1 number, 1 special char
 *    • Add members after group creation
 * ══════════════════════════════════════════════════════
 */

"use strict";

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "splitsmart_super_secret_change_in_prod_2024";
const JWT_EXPIRES = "7d";
const SALT_ROUNDS = 12;
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/splitsmart7";

// ══════════════════════════════════════════════════════
//  SCHEMAS
// ══════════════════════════════════════════════════════

// Admin (can do everything)
const adminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password_hash: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});
const Admin = mongoose.model("Admin", adminSchema);

// Viewer (read-only user — can see a specific group's data)
const viewerSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password_hash: { type: String, required: true },
  groupId: { type: String, required: true }, // which group they can view
  created_at: { type: Date, default: Date.now },
});
const Viewer = mongoose.model("Viewer", viewerSchema);

// Group — so multiple groups can exist
const groupSchema = new mongoose.Schema(
  {
    _id: { type: String }, // short id like "g_1234567890"
    name: { type: String, required: true, trim: true },
    created_at: { type: Date, default: Date.now },
  },
  { _id: false },
);
const Group = mongoose.model("Group", groupSchema);

// Member — now has groupId
const memberSchema = new mongoose.Schema(
  {
    _id: { type: Number },
    name: { type: String, required: true, trim: true },
    color: { type: String, required: true },
    groupId: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
  },
  { _id: false },
);
const Member = mongoose.model("Member", memberSchema);

// Expense — now has groupId + optional custom split/payer amounts
// payerAmounts:  { "memberId": amountTheyPaid, ... }   — if empty, split equally among payers
// splitAmounts:  { "memberId": amountTheyOwe, ... }    — if empty, split equally among splitAmong
const expenseSchema = new mongoose.Schema(
  {
    _id: { type: Number },
    description: { type: String, required: true, trim: true },
    amount: { type: Number, required: true },
    payers: { type: [Number], required: true },
    split_among: { type: [Number], required: true },
    emoji: { type: String, default: "🧾" },
    date: { type: String, required: true },
    groupId: { type: String, required: true },
    // Custom amounts — stored as plain objects { memberId: amount }
    payer_amounts: { type: Object, default: {} },
    split_amounts: { type: Object, default: {} },
    created_at: { type: Date, default: Date.now },
  },
  { _id: false },
);
const Expense = mongoose.model("Expense", expenseSchema);

// Payment — now has groupId
const settledSchema = new mongoose.Schema({
  from_id: { type: Number, required: true },
  to_id: { type: Number, required: true },
  amount: { type: Number, required: true },
  groupId: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});
const Settled = mongoose.model("Settled", settledSchema, "payments");

// ── Express ──────────────────────────────────────────
const app = express();
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(express.json());

// ── Auth Middleware ──────────────────────────────────
// Works for both admin and viewer tokens
function requireAuth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Missing or invalid Authorization header." });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    // req.user.role = 'admin' or 'viewer'
    next();
  } catch {
    return res
      .status(401)
      .json({ error: "Token expired or invalid. Please log in again." });
  }
}

// Admin-only middleware (viewers cannot use these routes)
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ error: "This action requires admin access." });
  }
  next();
}

// ── Shape Helpers ────────────────────────────────────
function docToExpense(doc) {
  return {
    id: doc._id,
    desc: doc.description,
    amount: doc.amount,
    payers: doc.payers,
    splitAmong: doc.split_among,
    emoji: doc.emoji,
    date: doc.date,
    groupId: doc.groupId,
    payerAmounts: doc.payer_amounts || {},
    splitAmounts: doc.split_amounts || {},
  };
}
function docToMember(doc) {
  return {
    id: doc._id,
    name: doc.name,
    color: doc.color,
    groupId: doc.groupId,
  };
}

// ══════════════════════════════════════════════════════
//  PASSWORD VALIDATION
//  Rules: min 8 chars, 1 uppercase, 1 number, 1 special char
// ══════════════════════════════════════════════════════
function validatePassword(password) {
  if (!password || password.length < 8) {
    return "Password must be at least 8 characters.";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password must contain at least one uppercase letter.";
  }
  if (!/[0-9]/.test(password)) {
    return "Password must contain at least one number.";
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return "Password must contain at least one special character (!@#$%^&* etc).";
  }
  return null; // null means valid
}

// ══════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════

app.get("/api", (req, res) => {
  res.json({
    message: "SplitSmart API is running 🚀",
    version: "4.0-multigroup",
  });
});

// ── Auth: Check if any admin exists ─────────────────
app.get("/api/auth/exists", async (req, res) => {
  try {
    const cnt = await Admin.countDocuments();
    res.json({ exists: cnt > 0 });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Database error. Make sure MongoDB is running." });
  }
});

// ── Auth: Register admin ─────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res
      .status(400)
      .json({ error: "Please enter a valid email address." });
  }

  const pwError = validatePassword(password);
  if (pwError) return res.status(400).json({ error: pwError });

  const cnt = await Admin.countDocuments();
  if (cnt > 0) {
    const header = req.headers["authorization"];
    if (!header || !header.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({
          error: "You must be logged in as an admin to add more admins.",
        });
    }
    try {
      const decoded = jwt.verify(header.slice(7), JWT_SECRET);
      if (decoded.role !== "admin") {
        return res
          .status(403)
          .json({ error: "Only admins can create admin accounts." });
      }
    } catch {
      return res.status(401).json({ error: "Token expired or invalid." });
    }
  }

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await Admin.create({
      email: email.toLowerCase().trim(),
      password_hash: hash,
    });
    res.status(201).json({ message: "Admin account created successfully." });
  } catch (err) {
    if (err.code === 11000) {
      return res
        .status(409)
        .json({ error: "An admin with this email already exists." });
    }
    res.status(500).json({ error: "Failed to create account." });
  }
});

// ── Auth: Register viewer (admin only) ──────────────
// POST /api/auth/register-viewer  { email, password, groupId }
app.post(
  "/api/auth/register-viewer",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const { email, password, groupId } = req.body || {};

    if (!email || !password || !groupId) {
      return res
        .status(400)
        .json({ error: "Email, password, and groupId are required." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res
        .status(400)
        .json({ error: "Please enter a valid email address." });
    }

    const pwError = validatePassword(password);
    if (pwError) return res.status(400).json({ error: pwError });

    // Check the group exists
    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ error: "Group not found." });

    try {
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      await Viewer.create({
        email: email.toLowerCase().trim(),
        password_hash: hash,
        groupId,
      });
      res.status(201).json({ message: "Viewer account created successfully." });
    } catch (err) {
      if (err.code === 11000) {
        return res
          .status(409)
          .json({ error: "A viewer with this email already exists." });
      }
      res.status(500).json({ error: "Failed to create viewer account." });
    }
  },
);

// ── Auth: Login (admin or viewer) ───────────────────
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    // Check admin first
    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (admin) {
      const ok = await bcrypt.compare(password, admin.password_hash);
      if (!ok)
        return res.status(401).json({ error: "Invalid email or password." });
      const token = jwt.sign(
        { adminId: admin._id.toString(), email: admin.email, role: "admin" },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES },
      );
      return res.json({ token, email: admin.email, role: "admin" });
    }

    // Check viewer
    const viewer = await Viewer.findOne({ email: email.toLowerCase().trim() });
    if (viewer) {
      const ok = await bcrypt.compare(password, viewer.password_hash);
      if (!ok)
        return res.status(401).json({ error: "Invalid email or password." });
      const token = jwt.sign(
        {
          viewerId: viewer._id.toString(),
          email: viewer.email,
          role: "viewer",
          groupId: viewer.groupId,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES },
      );
      return res.json({
        token,
        email: viewer.email,
        role: "viewer",
        groupId: viewer.groupId,
      });
    }

    return res.status(401).json({ error: "Invalid email or password." });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed." });
  }
});

// ── Admins: List ─────────────────────────────────────
app.get("/api/admins", requireAuth, requireAdmin, async (req, res) => {
  try {
    const admins = await Admin.find().sort({ created_at: 1 });
    res.json({ admins: admins.map((a) => ({ id: a._id, email: a.email })) });
  } catch (err) {
    res.status(500).json({ error: "Failed to list admins." });
  }
});

// ── Admins: Remove ───────────────────────────────────
app.delete("/api/admins/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (id === req.user.adminId) {
    return res
      .status(400)
      .json({ error: "You cannot remove your own admin account." });
  }
  const cnt = await Admin.countDocuments();
  if (cnt <= 1) {
    return res
      .status(400)
      .json({ error: "Cannot remove the last admin account." });
  }
  try {
    const result = await Admin.findByIdAndDelete(id);
    if (!result) return res.status(404).json({ error: "Admin not found." });
    res.json({ message: "Admin removed.", id });
  } catch (err) {
    res.status(500).json({ error: "Failed to remove admin." });
  }
});

// ── Viewers: List (for a group) ──────────────────────
app.get(
  "/api/viewers/:groupId",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const viewers = await Viewer.find({ groupId: req.params.groupId }).sort({
        created_at: 1,
      });
      res.json({
        viewers: viewers.map((v) => ({ id: v._id, email: v.email })),
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to list viewers." });
    }
  },
);

// ── Viewers: Remove ──────────────────────────────────
app.delete("/api/viewers/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await Viewer.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: "Viewer not found." });
    res.json({ message: "Viewer removed." });
  } catch (err) {
    res.status(500).json({ error: "Failed to remove viewer." });
  }
});

// ── Groups: List ─────────────────────────────────────
app.get("/api/groups", requireAuth, requireAdmin, async (req, res) => {
  try {
    const groups = await Group.find().sort({ created_at: 1 });
    res.json({ groups: groups.map((g) => ({ id: g._id, name: g.name })) });
  } catch (err) {
    res.status(500).json({ error: "Failed to list groups." });
  }
});

// ── Groups: Create ───────────────────────────────────
app.post("/api/groups", requireAuth, requireAdmin, async (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "Group name is required." });
  }
  const id = "g_" + Date.now();
  try {
    const group = await Group.create({ _id: id, name: name.trim() });
    res.status(201).json({ id: group._id, name: group.name });
  } catch (err) {
    res.status(500).json({ error: "Failed to create group." });
  }
});

// ── Dashboard: All data for one group ────────────────
// Viewers get their assigned groupId from their token
// Admins must pass ?groupId=xxx
app.get("/api/dashboard", requireAuth, async (req, res) => {
  let groupId;
  if (req.user.role === "viewer") {
    groupId = req.user.groupId;
  } else {
    groupId = req.query.groupId;
    if (!groupId)
      return res
        .status(400)
        .json({ error: "groupId query parameter is required." });
  }

  try {
    const [members, expenses, settled] = await Promise.all([
      Member.find({ groupId }).sort({ created_at: 1 }),
      Expense.find({ groupId }).sort({ created_at: 1 }),
      Settled.find({ groupId }),
    ]);
    res.json({
      members: members.map(docToMember),
      expenses: expenses.map(docToExpense),
      payments: settled.map((s) => ({
        fromId: s.from_id,
        toId: s.to_id,
        amount: s.amount,
      })),
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ error: "Failed to load dashboard data." });
  }
});

// ── Members: Add ─────────────────────────────────────
app.post("/api/members", requireAuth, requireAdmin, async (req, res) => {
  const { id, name, color, groupId } = req.body || {};
  if (!id || !name || !color || !groupId) {
    return res
      .status(400)
      .json({ error: "id, name, color, and groupId are required." });
  }
  try {
    const existing = await Member.findOne({
      groupId,
      name: {
        $regex: new RegExp(
          `^${name.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
          "i",
        ),
      },
    });
    if (existing) {
      return res
        .status(409)
        .json({
          error: `A member named "${name}" already exists in this group.`,
        });
    }
    const member = await Member.create({
      _id: id,
      name: name.trim(),
      color,
      groupId,
    });
    res.status(201).json(docToMember(member));
  } catch (err) {
    res.status(500).json({ error: "Failed to add member." });
  }
});

// ── Members: Remove ──────────────────────────────────
app.delete("/api/members/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid member ID." });
  try {
    const result = await Member.findByIdAndDelete(id);
    if (!result) return res.status(404).json({ error: "Member not found." });
    res.json({ message: "Member removed.", id });
  } catch (err) {
    res.status(500).json({ error: "Failed to remove member." });
  }
});

// ── Expenses: Add ────────────────────────────────────
app.post("/api/expenses", requireAuth, requireAdmin, async (req, res) => {
  const {
    id,
    desc,
    amount,
    payers,
    splitAmong,
    emoji,
    date,
    groupId,
    payerAmounts,
    splitAmounts,
  } = req.body || {};

  if (!id || !desc || !amount || !payers || !splitAmong || !groupId) {
    return res
      .status(400)
      .json({
        error:
          "id, desc, amount, payers, splitAmong, and groupId are required.",
      });
  }
  if (typeof amount !== "number" || amount <= 0) {
    return res.status(400).json({ error: "Amount must be a positive number." });
  }

  try {
    await Expense.create({
      _id: id,
      description: desc.trim(),
      amount,
      payers,
      split_among: splitAmong,
      emoji: emoji || "🧾",
      date: date || new Date().toISOString(),
      groupId,
      payer_amounts: payerAmounts || {},
      split_amounts: splitAmounts || {},
    });
    res.status(201).json({ message: "Expense added.", id });
  } catch (err) {
    console.error("Add expense error:", err);
    res.status(500).json({ error: "Failed to add expense." });
  }
});

// ── Expenses: Delete single expense ──────────────────
app.delete("/api/expenses/:id", requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid expense ID." });
  try {
    const result = await Expense.findByIdAndDelete(id);
    if (!result) return res.status(404).json({ error: "Expense not found." });
    res.json({ message: "Expense deleted.", id });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete expense." });
  }
});

// ── Expenses: Delete all (after settlement) ──────────
app.delete("/api/expenses/all", requireAuth, requireAdmin, async (req, res) => {
  const { groupId } = req.body || {};
  if (!groupId) return res.status(400).json({ error: "groupId is required." });
  try {
    await Expense.deleteMany({ groupId });
    await Settled.deleteMany({ groupId });
    res.json({ message: "All expenses cleared after settlement." });
  } catch (err) {
    res.status(500).json({ error: "Failed to clear expenses." });
  }
});

// ── Payments: Record ─────────────────────────────────
app.post("/api/settled", requireAuth, requireAdmin, async (req, res) => {
  const { fromId, toId, amount, groupId } = req.body || {};
  if (
    !fromId ||
    !toId ||
    typeof amount !== "number" ||
    amount <= 0 ||
    !groupId
  ) {
    return res
      .status(400)
      .json({ error: "fromId, toId, amount, and groupId are required." });
  }
  try {
    await Settled.create({ from_id: fromId, to_id: toId, amount, groupId });
    res.json({ message: "Payment recorded." });
  } catch (err) {
    res.status(500).json({ error: "Failed to record payment." });
  }
});

// ── Settled: Clear all ───────────────────────────────
app.delete("/api/settled", requireAuth, requireAdmin, async (req, res) => {
  const { groupId } = req.body || {};
  if (!groupId) return res.status(400).json({ error: "groupId is required." });
  try {
    await Settled.deleteMany({ groupId });
    res.json({ message: "Settled transactions cleared." });
  } catch (err) {
    res.status(500).json({ error: "Failed to clear." });
  }
});

// ── Group: Dissolve (wipe members + expenses + settled) ──
app.delete(
  "/api/group/:groupId",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const { groupId } = req.params;
    try {
      await Promise.all([
        Settled.deleteMany({ groupId }),
        Expense.deleteMany({ groupId }),
        Member.deleteMany({ groupId }),
        Group.findByIdAndDelete(groupId),
      ]);
      res.json({ message: "Group dissolved." });
    } catch (err) {
      res.status(500).json({ error: "Failed to dissolve group." });
    }
  },
);

// ── Frontend Static Files ────────────────────────────
app.use(express.static(path.join(__dirname, "proj3", "dist")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "proj3", "dist", "index.html"));
});

// ── 404 API ──────────────────────────────────────────
app.use("/api/*", (req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found.` });
});

app.use((err, req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error." });
});

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("  ✓ MongoDB connected.");
    app.listen(PORT, () => {
      console.log(`
  ██████████████████████████████████████████
  ▌  SplitSmart Backend  v4.0-multigroup  ▐
  ▌  http://localhost:${PORT}               ▐
  ██████████████████████████████████████████
      `);
    });
  })
  .catch((err) => {
    console.error("\n  ❌  Failed to connect to MongoDB:\n", err.message);
    process.exit(1);
  });

module.exports = app;
