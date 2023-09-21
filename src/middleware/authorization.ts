import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { createCustomError } from "../errors/customAPIError";
import InfluencerMaster from "../model/InfluencerMaster";
import AgencyMaster from "../model/AgencyMaster";
import BrandMaster from "../model/BrandMaster";
import User from "../model/User";

const errorMessage = "You do not have permissions to perform this action";

const authorization = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer")) {
        const message = "Unauthenticaded No Bearer";
        return next(createCustomError(message, 401));
    }

    const token = authHeader.split(" ")[1];
    try {
        const payload: string | jwt.JwtPayload | any = jwt.verify(token, process.env.JWT_SECRET);
        const user: any = await User.findOne({ isActive: true, _id: payload.userId });
        const influencer = await InfluencerMaster.findOne({ isActive: true, _id: payload.influencerId });
        const brand = await BrandMaster.findOne({ isActive: true, _id: payload.brandId });
        const agency = await AgencyMaster.findOne({ isActive: true, _id: payload.agencyId });

        if (!user && !influencer && !brand && !agency) {
            return next(createCustomError("Invalid JWT"));
        }

        if (user && user.changePasswordAfter(payload.iat)) {
            return next(createCustomError("User recently changed the password, Please login again", 401));
        } else if (user) {
            req.user = { userId: payload.userId, details: user ,type:"user" };
        }

        if (influencer) {
            req.user = { userId: payload.influencerId, details: influencer, type:"influencer" };
        }
        if (brand) {
            req.user = { userId: payload.brandId, details: brand ,type:"brand" };
        }
        if (agency) {
            req.user = { userId: payload.agencyId, details: agency,type:"agency" };
        }
        next();
    } catch (error) {
        let message: string;
        if (error instanceof jwt.TokenExpiredError) {
            message = "Token Expired";
        } else {
            message = "Authentication failed invalid JWT";
        }

        return next(createCustomError(message, 401));
    }
};

const restrictTo = (
    option: "masters" | "campaign" | "adminSettings" | "scheduler" | "support" | "transactions" | "admin"
) => {
    return (req: Request, res: Response, next: NextFunction) => {
        const { permissions } = req.user.details;
        if (!permissions) {
            return next(createCustomError(errorMessage, 403));
        }

        if (option === "admin") {
            if (permissions.admin) {
                return next();
            }
            return next(createCustomError(errorMessage, 403));
        }

        if (permissions.admin) {
            return next();
        }

        const checkFrom = permissions[option];
        if (!checkFrom || checkFrom.length !== 2) {
            return next(createCustomError(errorMessage, 403));
        }

        //checkFrom[1] = can edit;
        //checkFrom[0] = can view;
        if (checkFrom[1]) {
            return next();
        }

        if (req.method === "GET" && checkFrom[0]) {
            return next();
        }

        return next(createCustomError(errorMessage, 403));
    };
};

export { authorization as default, restrictTo };
