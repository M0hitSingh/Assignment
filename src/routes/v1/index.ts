import express from "express";
import { sendSuccessApiResponse } from "../../middleware/successApiResponse";

import authRoute from "./auth.route";

/**
 * Endpoint: /api/v1
 */
const router = express.Router();

router.use("/auth", authRoute);

router.get("/", (req, res) => {
    const response = sendSuccessApiResponse({ message:" V1 API is running" });
    res.status(200).send(response);
});

export default router;
