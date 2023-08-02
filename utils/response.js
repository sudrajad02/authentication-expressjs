const response = (res, code, message, data) => {
    return res.status(code).json({
        code: code,
        message: message, 
        data: code == 200 ? data:undefined,
        error: code != 200 ? data:undefined
    })
}

module.exports = response