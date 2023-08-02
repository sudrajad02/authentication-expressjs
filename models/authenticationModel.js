const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

class authenticationModel {
    async user(data) {
        try {
            const user = await prisma.user.findFirst({
                where: {
                    email: data.email
                }
            })
    
            return user   
        } catch (error) {
            return error
        }
    }

    async register(data) {
        try {
            const user = await prisma.user.create({
                data: {
                    name: data.name,
                    email: data.email,
                    password: data.password
                }
            })

            return user
        } catch (error) {
            return error
        }
    }
}

module.exports = new authenticationModel()