import { Request, Response } from "express";
import { User } from "../models/User";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { UniqueConstraintError } from "sequelize";

dotenv.config();

const SECRET_KEY = process.env.JWT_SECRET || "secret_key";

//📌 1️⃣ NEW USER  SIGNUP 

export const signup = async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password, termsAccepted } = req.body;

    // Validate input
    if (!name || !email || !password || typeof termsAccepted !== 'boolean') {
      res.status(400).json({ error: "All fields are required and termsAccepted must be boolean." });
      return;
    }
    // Basic email format validation
    const emailRegex = /^\S+@\S+\.\S+$/;
    if (!emailRegex.test(email)) {
      res.status(400).json({ error: "Invalid email format." });
      return;
    }
    // termsAccepted exists in the DB, but by natural expectation this should always be true,
    // so storing this field in the database is redundant — it should never be false (just thought I'd mention it)
    if (!termsAccepted) {
      res.status(400).json({ error: "Terms and conditions must be accepted." });
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user (let DB handle unique constraint)
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      termsAccepted,
    });

    // Prepare response user object (exclude password)
    const responseUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
    };

    res.status(201).json({ message: "User registered successfully", user: responseUser });
  } catch (error: any) {
    // Handle unique constraint error
    if (error instanceof UniqueConstraintError) {
      res.status(400).json({ error: "Email is already registered." });
    } else {
      console.error(error);
      res.status(500).json({ error: "Error registering user" });
    }
  }
};
  

// 📌 2️⃣ Login 
export const login = async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body;
  
      // Search new user
      const user = await User.findOne({ where: { email } });
      if (!user) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }
  
      // Check password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }
  
      // ✅ Create JWT
      const token = jwt.sign({ id: user.id }, "your_secret_key", { expiresIn: "1h" });
  
      res.json({ message: "Login successful!", token });
    } catch (error) {
      res.status(500).json({ error: "Error logging in" });
    }
  };
  
