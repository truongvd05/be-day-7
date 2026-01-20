const exceptionHandler = (err, _, res, next) => {
    console.error(err);
    res.status(500).json({
        status: "error",
        message: "Internal server error",
        timestamp: new Date().toISOString(),
    });
};

export default exceptionHandler;
