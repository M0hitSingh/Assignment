import { NextFunction, Request, RequestHandler, Response } from "express";

const asyncWrapper = (
    fn: (req: Request, res: Response, next: NextFunction) => Promise<Response | void>
): RequestHandler => {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            await fn(req, res, next);
        } catch (error) {
            next(error);
        }
    };
};

export = asyncWrapper;
