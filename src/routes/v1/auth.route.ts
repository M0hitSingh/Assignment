import express from "express";
import {
    forgotPassword,
    instagramAuth,
    loginUser,
    otpLogin,
    refreshToken,
    registerOtp,
    registerUser,
    resetPassword,
    tokenValid,
    updatePassword,
    verifyOtp,
    youtubeAuth,
    loginBrand,
    brandSetPassword,
    brandResetPassword,
    brandUpdatePassword,
    brandForgotPassword,
    loginAgency,
    agencyForgotPassword,
    agencySetPassword,
    agencyResetPassword,
    agencyUpdatePassword,
} from "../../controllers/auth.controller";
import authorization, { restrictTo } from "../../middleware/authorization";

/**
 * Endpoint: /api/v1/auth
 */
const router = express.Router();

const RESTICT_TO = "admin";

router.route("/refresh-token").get(refreshToken);

// User
router.route("/register").post(authorization, restrictTo(RESTICT_TO), registerUser);
router.route("/login").post(loginUser);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password/:token").patch(resetPassword).get(tokenValid);
router.route("/update-password").patch(authorization, updatePassword);

// Influencer
router.route("/otp-login").post(otpLogin);
router.route("/otp-verify").post(verifyOtp);
router.route("/otp-register").post(registerOtp);

router.route("/instagram").get(instagramAuth).post(instagramAuth);
router.route("/youtube").get(youtubeAuth).post(youtubeAuth);

// Brand
router.route("/brand/login").post(loginBrand);
router.route("/brand/forgot-password/").post(brandForgotPassword);
router.route("/brand/set-password").post(brandSetPassword);
router.route("/brand/reset-password/:token").patch(brandResetPassword);
router.route("/brand/update-password/").patch(authorization, brandUpdatePassword);

// Agency
router.route("/agency/login").post(loginAgency);
router.route("/agency/forgot-password/").post(agencyForgotPassword);
router.route("/agency/set-password").post(agencySetPassword);
router.route("/agency/reset-password/:token").patch(agencyResetPassword);
router.route("/agency/update-password/").patch(authorization, agencyUpdatePassword);

export default router;
