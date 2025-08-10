import sendEmail from "../config/sendEmail.js";
import UserModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";





export async function registerUserController(req, res) {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({
                message: "TODOS ESTES CAMPOS SÃO OBRIGATORIOS",
                error: true,
                success: false
            });
        }

        const user = await UserModel.findOne({ email });

        if (user) {
            return res.json({
                message: "EMAIL JA EXISTE",
                error: true,
                success: false
            })
        }

        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);

        const payload = {
            name,
            email,
            password: hashPassword
        };

        const newUser = new UserModel(payload);
        const save = await newUser.save();

        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save._id}`;

        const verifyEmail = await sendEmail({
            sendTo: email,
            subject: "Verifique seu email",
            html: verifyEmailTemplate({
                name,
                url: VerifyEmailUrl,
            })
        })

        return res.json({
            message: "USUARIO CADASTRADO COM SUCESSO",
            error: false,
            sucess: true,
            data: save,
        })

    } catch (error) {
        return res.status(500).json({
            message: error.message || Error,
            error: true,
            success: false
        });
    }
};
