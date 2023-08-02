const bcrypt = require('bcrypt')
const Joi = require('joi')
const jwt = require('jsonwebtoken')

const authModel = require('../models/authenticationModel')
const response = require('../utils/response')

const schema_login = Joi.object({
    email: Joi.string().required().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }),
    password: Joi.string().required().min(6)
})

const schema_register = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().required().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }),
    password: Joi.string().required().min(6)
})

class authtenticationServices {
    tokenChecker(req, res, next) {
        try {
            let token_header = req.headers.authorization

            if (!token_header) {
                throw {
                    code: 401,
                    status: false,
                    message: "please login",
                }
            }
    
            if (token_header.split(' ')[0] !== 'Bearer') {
                throw {
                    code: 500,
                    status: false,
                    message: "incorrect token format",
                }
            }
    
            let token = token_header.split(' ')[1];
    
            if (!token) {
            	throw {
            		code: 401,
                    status: false,
            		message: "no token provided"
            	};
            }
    
            jwt.verify(token, process.env.PRIVATE_KEY, (err, decoded) => {
            	if (err) {
            		throw {
            			code: 500,
                        status: false,
            			message: err
            		}
            	}

                req.decoded = decoded;

            	next();
            });
        } catch (error) {
            return response(res, error.code, "error", error.message)
        }
	}

    async login(req, res, next) {
        try {
            const result = schema_login.validate({
                email: req.body.email,
                password: req.body.password
            });

            if (result.error) {
                throw {
                    code: 401,
                    status: false,
                    message: result.error.details[0].message.replace(/['"]/g, '')
                }
            }

            const user = await authModel.user(req.body)

            if (!user) {
                throw {
                    code: 404,
                    status: false,
                    message: "email not found"
                }
            }

            const check_password = await bcrypt.compare(req.body.password, user.password)

            if (!check_password) {
                throw {
                    code: 401,
                    status: false,
                    message: "wrong password"
                }
            }

            const payload = {
                email: user.email
            }

            const token = jwt.sign(payload, process.env.PRIVATE_KEY, {
                expiresIn: process.env.TOKEN_EXPIRED
            })

            return response(res, 200, "success", {
                token
            })
        } catch (error) {
            return response(res, error.code, "error", error.message)
        }
    }

    async register(req, res, next) {
        try {
            const result = schema_register.validate(req.body);
    
            if (result.error) {
                throw {
                    code: 404,
                    status: false,
                    message: result.error.details[0].message.replace(/['"]/g, '')
                }
            }
    
            const register = await authModel.register({
                name: req.body.name,
                email: req.body.email,
                password: await bcrypt.hash(req.body.password, 12),
            })

            if (register.code == "P2002") {
                if (register.meta.target == "User_email_key") {
                    throw {
                        code: 401,
                        status: false,
                        message: "email is registered"
                    }
                }
            }
    
            return response(res, 200, "success", register)
        } catch (error) {
            return response(res, error.code, "error", error.message)
        }
    }

    async detailUser(req, res, next) {
        try {
            const user = await authModel.user({ email: req.decoded.email })
            
            return response(res, 200, "success", user)
        } catch (error) {
            return response(res, error.code, "error", error.message)
        }
    }
}

module.exports = new authtenticationServices()