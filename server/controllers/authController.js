import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";

// For Register
export const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: "Missing Details" });
  }

  try {
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res.json({ status: false, message: "User already exist." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new userModel({ name, email, password: hashedPassword });
    await user.save();

    // generated a token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // generated a cookie with name 'token'and it's value token.
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // sending welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to X Website",
      text: `Welcome to X website. Your account has been created with ${email} successfully.`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true });
  } catch (error) {
    res.json({ status: false, message: error.message });
  }
};

// For Login
export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.json({
      success: false,
      message: "Email and Password are required",
    });

  try {
    const user = await userModel.findOne({ email });

    if (!user)
      return res.json({
        success: false,
        message: "Email or Password is Invalid",
      });

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.json({
        success: false,
        message: "Email or Password is Invalid",
      });

    // generated a token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // generated a cookie with name 'token' and it's value token.
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// For Logout
export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    return res.json({ success: true, message: "Logged Out" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// Send verification OTP to user's Email
export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await userModel.findById(userId);
    if (user.isAccountVerified) {
      return res.json({ success: false, message: "Account already verified" });
    }

    // Generating 6 digit random number for OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. Verify your account with the given OTP.`,
    };

    await transporter.sendMail(mailOption);
    res.json({ seccuss: true, message: "Verification OTP sent on your Email" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// Verify account using received OTP
export const verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.json({ seccuss: false, message: "OTP not received" });
  }
  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }
    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;
    await user.save();

    return res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// check if user is authenticated
export const isAuthenticated = async (req, res) => {
  try {
    return res.json({ seccuss: true, message: "Authenticated account." });
  } catch (error) {
    return res.json({ seccuss: false, message: error.message });
  }
};

// send password Reset OTP
export const sendResetOtp = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.json({ seccuss: false, message: "Email required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ seccuss: false, message: "User not found" });
    }

    // Generating 6 digit random number for OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Resent OTP",
      text: `Your OTP for resetting password is ${otp}. Use this OTP to reset password.`,
    };

    await transporter.sendMail(mailOption);
    res.json({ seccuss: true, message: "OTP sent to your Email" });
  } catch (error) {
    return res.json({ seccuss: false, message: error.message });
  }
};
