const notFoundHandler = (_, res) => {
    return res.error("Resource not found", 404);
};

export default notFoundHandler;
