import crypto from "crypto";
import { NextFunction, Request, RequestHandler, Response } from "express";
import jwt from "jsonwebtoken";

import { createCustomError } from "../errors/customAPIError";
import asyncWrapper from "../middleware/asyncWrapper";
import { sendSuccessApiResponse } from "../middleware/successApiResponse";

import User from "../model/User";


interface signupObject {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    phoneNumber: string;
    gender: string;
    isDefaultUser?: boolean;
    role: any;
    createdBy: string;
    modifiedBy: string;
}

const refreshToken: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer")) {
        const message = "Unauthenticaded No Bearer";
        return next(createCustomError(message, 401));
    }

    let data: any;
    const token = authHeader.split(" ")[1];
    try {
        const payload: string | jwt.JwtPayload | any = jwt.verify(token, process.env.JWT_SECRET);
        data = await getNewToken(payload);
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            const payload: any = jwt.decode(token, { complete: true }).payload;
            data = await getNewToken(payload);

            if (!data) {
                const message = "Authentication failed invalid JWT";
                return next(createCustomError(message, 401));
            }
        } else {
            const message = "Authentication failed invalid JWT";
            return next(createCustomError(message, 401));
        }
    }

    res.status(200).json(sendSuccessApiResponse(data, 200));
});

const getNewToken = async (payload: any) => {
    const isUser = payload?.userId ? true : false;


    let data: any;
    if (isUser) {
        const user: any = await User.findOne({ isActive: true, _id: payload.userId });
        if (user) {
            data = { token: user.generateJWT() };
        }
    }

    return data;
};

const registerUser: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const createdBy = req.user.userId;

    const {
        firstName,
        lastName,
        email,
        password,
        phoneNumber,
        gender,
        role,
    }: {
        firstName: string;
        lastName: string;
        email: string;
        username: string;
        password: string;
        phoneNumber: string;
        gender: string;
        role: string;
        permissions: {
            admin?: boolean;
            masters?: [boolean, boolean];
            campaign?: [boolean, boolean];
            scheduler?: [boolean, boolean];
            transactions?: [boolean, boolean];
            adminSettings?: [boolean, boolean];
            support?: [boolean, boolean];
        };
    } = req.body;

    const toStore: signupObject = {
        firstName,
        lastName,
        email,
        password,
        phoneNumber,
        gender,
        role,
        createdBy,
        modifiedBy: createdBy,
    };

    const emailisActive = await User.findOne({ email, isActive: true });
    if (emailisActive) {
        const message = "Email is already registered";
        return next(createCustomError(message, 406));
    }


    const phoneNumberisActive = await User.findOne({ phoneNumber, isActive: true });

    if (phoneNumberisActive) {
        const message = "Phone number is already registered";
        return next(createCustomError(message, 406));
    }
    const user: any = await User.create(toStore);
    user.password = undefined;
    const data = { created: true, user, token: user.generateJWT() };
    res.status(201).json(sendSuccessApiResponse(data, 201));
});

const loginUser: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { email, password }: { email: string; password: string } = req.body;
    const emailExists: any = await User.findOne(
        { email, isActive: true },
        "firstName lastName email username password role"
    );
    if (emailExists) {
        const isPasswordRight = await emailExists.comparePassword(password);
        if (!isPasswordRight) {
            const message = "Invalid credentials";
            return next(createCustomError(message, 401));
        }
    
        const data = {
            canLogIn: true,
            firstName: emailExists.firstName,
            lastName: emailExists.lastName,
            email: emailExists.email,
            username: emailExists.username,
            token: emailExists.generateJWT(),
        };
    
        res.status(200).json(sendSuccessApiResponse(data));    
    }
    else {
        const message = "Invalid credentials";
        return next(createCustomError(message, 401));
    }

});

const forgotPassword: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { email }: { email: string } = req.body;
    const user: any = await User.findOne({ email, isActive: true });
    if (!user) {
        const message = `No user found with the email: ${email}`;
        return next(createCustomError(message, 400));
    }
    const resetToken: string = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // const resetURL = `${req.protocol}://${req.get("host")}/api/v1/auth/reset-password/${resetToken}`;
    // const resetURL = `${req.protocol}://${process.env.PASSWORD_RESET_URL}/${resetToken}`;
    const resetURL = `${process.env.PASSWORD_RESET_URL}/${resetToken}`;

    const placeHolderData = {
        name: user.firstName,
        resetPasswordLink: resetURL,
    };

    try {
        await sendEmailNotification("RESET_PASSWORD", email, placeHolderData);
        // user.passwordResetToken = resetToken;
        // user.passwordResetExpires = addMinutes(new Date(), 10);
        // await user.save({ validateBeforeSave: false });
        await User.findByIdAndUpdate(user._id, {
            passwordResetToken: resetToken,
        });

        const body = { message: `Token sent to email ${email}` };
        const response = sendSuccessApiResponse(body);
        res.status(200).json(response);
    } catch (error) {
        user.passwordResetExpires = undefined;
        user.passwordResetToken = undefined;
        await user.save({ validateBeforeSave: false });
        const message = "There was an error in sending email";
        return next(createCustomError(message));
    }
});

const tokenValid: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.params;
    // const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
        passwordResetToken: token,
        isActive: true,
        passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
        const message = "Invalid token or Token expired";
        return next(createCustomError(message));
    }

    const data = { canChangePassword: true, email: user.email };
    const response = sendSuccessApiResponse(data);
    res.status(200).json(response);
});

const resetPassword: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.params;
    // const hashedtoken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
        passwordResetToken:token,
        isActive: true,
        passwordResetExpires: { $gt: Date.now() },
    });
    if (!user) {
        const message = "Invalid token or Session expired";
        return next(createCustomError(message));
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();
    res.json({ message: "Password changed successfully", token: user.generateJWT() });
});

const updatePassword: RequestHandler = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { currentPassword, newPassword }: { currentPassword: string; newPassword: string } = req.body;
    const id = req.user.userId;
    const user: any = await User.findOne({ isActive: true, _id: id });
    if (!user) {
        const message = "There was an error finding the email";
        return next(createCustomError(message, 401));
    }

    const isCurrentPasswordCorrect = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordCorrect) {
        const message = "Invalid current password";
        return next(createCustomError(message, 400));
    }

    user.password = newPassword;
    await user.save();

    const data = { updatedPassword: true, email: user.email };
    const response = sendSuccessApiResponse(data);
    res.status(200).json(response);
});

// Brand

export {
    registerUser,
    loginUser,
    forgotPassword,
    resetPassword,
    tokenValid,
    updatePassword,
    refreshToken,
};
