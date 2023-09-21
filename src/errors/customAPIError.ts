/* eslint-disable @typescript-eslint/ban-types */
class customAPIError extends Error {
    [x: string]: any;
    status: { code: number; message: string };
    isOperational: Boolean;
    path: any;
    value: any;

    constructor(message: string, statusCode: number = 500) {
        super(message);
        this.status = { code: statusCode, message: `${statusCode}`.startsWith("4") ? "fail" : "error" };
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}

const createCustomError = (message: string, statusCode: number = 500) => {
    return new customAPIError(message, statusCode);
};

export { customAPIError, createCustomError };
