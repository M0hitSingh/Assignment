/* eslint-disable @typescript-eslint/ban-types */
class successApiResponse {
    constructor(statusCode: number = 200) {
        this.status = { code: statusCode, message: "success" };
        this.data = {};
        this.error = {};
    }
    data: unknown | {};
    error: unknown | {};
    status: unknown | {};
}

const sendSuccessApiResponse = (data: Record<string, any>, statusCode: number = 200) => {
    const newApiResponse = new successApiResponse(statusCode);
    newApiResponse.data = data;
    return newApiResponse;
};

export { sendSuccessApiResponse, successApiResponse };
