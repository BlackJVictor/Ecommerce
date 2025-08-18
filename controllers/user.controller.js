import sendEmail from "../config/sendEmail.js";
import UserModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import generatedAccessToken from "../utils/generatedAccessToken.js";
import generatedRefreshToken from "../utils/generatedRefreshToken.js";
import uploadImageCloudnary from "../utils/UploadImageCloudnary.js";
import generatedOtp from "../utils/generatedOtp.js";
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js';
import jwt from "jsonwebtoken";


export async function registerUserController(req, res) {
    try {

        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({
                message: "TODOS ESTES CAMPOS SÃO OBRIGATORIOS",
                error: true,
                success: false,
            });
        }

        const user = await UserModel.findOne({ email });

        if (user) {
            return res.json({
                message: "EMAIL JA EXISTE",
                error: true,
                success: false,
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

        const VerifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`;

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
            success: true,
            data: save,
        })

    } catch (error) {
        return res.status(500).json({
            message: error.message || Error,
            error: true,
            success: false,
        });
    }
};


export async function verifyEmailController(req, res) {
    try {
        const { code } = req.body;
        const user = await UserModel.findOne({ _id: code });

        if (!user) {
            return res.status(400).json({
                message: "CODIGO INVALIDO",
                error: true,
                success: false,
            });
        }

        const updateUser = await UserModel.findOne({ _id: code },
            {
                verify_email: true
            },
        );
        return res.json({
            message: "EMAIL VERIFICADO COM SUCESSO",
            success: true,
            error: false,
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || Error,
            error: true,
            success: false,
        });
    }
}

export async function loginController(req, res) {
    try {

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "TODOS OS CAMPOS SÃO OBRIGATORIOS",
                error: true,
                success: false,
            });
        }


        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.json({
                message: "ESTE USUARIO NAO EXISTE",
                error: true,
                success: false,
            });
        }

        if (user.status !== "Active") {
            return res.status(400).json({
                message: "ENTRE EM CONTATO COM O SEU ADMINISTRADOR",
                error: true,
                success: false,
            });

        }

        const checkPassword = await bcrypt.compare(password, user.password);

        if (!checkPassword) {
            return res.status(400).json({
                message: "SENHA INCORRETA TENTE NOVAMENTE OU DIGITE A SENHA CORRETAMENTE",
                error: true,
                success: false,
            });
        }

        const accessToken = await generatedAccessToken(user.id);
        const refreshToken = await generatedRefreshToken(user.id);

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "None",
        };

        res.cookie("accessToken", accessToken, cookieOptions);
        res.cookie("refreshToken", refreshToken, cookieOptions);



        return res.json({
            message: "LOGADO COM SUCESSO",
            success: true,
            error: false,
            data: {
                accessToken,
                refreshToken,
            },
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false,
        })
    }
}

    

export async function logoutController(req, res) {
    try {
        
        const userId = req.userId;
        console.log("UserID no logoutController:", userId); 

           const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "None"
        };
        
        if (!userId) {
            console.log("Erro: userId não encontrado. Ação de logout no banco de dados não será executada.");
            res.clearCookie("accessToken", cookieOptions);
            res.clearCookie("refreshToken", cookieOptions);
            return res.status(400).json({
                message: "Acesso não autorizado ou sessão já encerrada.",
                error: true,
                success: false,
            });
        }
        
     

        res.clearCookie("accessToken", cookieOptions);
        res.clearCookie("refreshToken", cookieOptions);

        
        const removeRefreshToken = await UserModel.findByIdAndUpdate(userId, {
            refresh_token : ""
        });

        
        console.log("Resultado da remoção do token:", removeRefreshToken);

        return res.json({
            message: "SAINDO DO SISTEMA COM SEGURANÇA",
            success: true,
            error: false,
        });

    } catch (error) {
        
        console.error("Erro durante o logout:", error);
        return res.status(500).json({
            message: "Algo deu errado durante o logout.",
            error: true,
            success: false,
        });
    }
}

export async function uploadAvatar(req, res) {
    try {
        const userId = req.userId
        const image = req.file

        const upload = await uploadImageCloudnary(image)

        const updateUser = await UserModel.findByIdAndUpdate(userId,{
            avatar : upload.url
        });
        return res.json({
            message: "carregando perfil",
            success: true,
            error: false,
            data : {
                _id : userId,
                avatar : upload.url
            }
        });
    }catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error: true,
            success: false,
        });
    }
}

export async function updateUserDetails(req, res) {
    try {
        const userId = req.userId
        const { name, email, mobile, password } = req.body

        let hashPassword = ""

        if(password){
            const salt = await bcrypt.genSalt(10)
            hashPassword = await bcrypt.hash(password,salt)
        }

        const updateUser = await UserModel.updateOne({ _id : userId},{
            ...(name && {name : name }),
            ...(email && {email : email}),
            ...(mobile && {mobile : mobile}),
            ...(password && {password : hashPassword})
        })
        return res.json({
            message: "ATUALIZADO COM SUCESSO",
            error : false,
            success : true,
            data : updateUser
        })

    }catch (error){
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

export async function forgotPasswordController(req, res) {
    try {
        const { email } = req.body

        const user = await UserModel.findOne({ email })

        if(!user){
            return res.status(400).json({
                message: "E-mail não disponivel",
                error: true,
                sucess: false
            })
        }

        const otp = generatedOtp()
        const expireTime = new Date().getTime() + 60 * 60 * 1000

        const update = await UserModel.findByIdAndUpdate(user._id,{
            forgot_password_otp : otp,
            forgot_password_expiry : new Date(expireTime).toISOString()
        })

        await sendEmail({
            sendTo: email,
            subject: "ESQUECEU SUA SENHA?",
            html : forgotPasswordTemplate({
                name : user.name,
                otp : otp
        })
    })
    
    return res.json({
        message : "FAVOR CHECAR SEU EMAIL",
        error : false,
        success : true
    })

} catch (error) {
    return res.status(500).json({
        message : error.message || error,
        error : true,
        success: false
        })
    }
}

export async function verifyForgotPasswordOtp(req, res) {
    try{
        const {email, otp } = req.body

        if(!email || !otp){
            return res.status(400).json({
                message: "Forneça o campo obrigatório e-mail, otp.",
                error: true,
                success: false
            })
        }

        const user = await UserModel.findOne({ email})

        if(!user){
            return res.status(400).json({
                message: "E-mail não disponivel",
                error: true,
                success: false
            })
        }

        const currentTime = new Date().toISOString()

        if(user.forgot_password_expiry < currentTime ){
            return res.status(400).json({
                message:"Otp expirou",
                error: true,
                success: false
            })
        }

        if(otp !== user.forgot_password_otp){
            return res.status(400).json({
                message: "OtP invalido",
                error: true,
                success: false
            })
        }

        const updateUser = await UserModel.findByIdAndUpdate(user?._id,{
            forgot_password_otp : "",
            forgot_password_expiry : ""
        })

        return res.json({
            message: "verificação otp com sucesso",
            error : false,
            success: true
        })
    }catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error:true,
            success: false
        })
    }
}

export async function resetpassword(req,res) {
    try {
        const { email , newPassword , confirmPassword } = req.body

        if(!email || !newPassword || !confirmPassword) {
            return res.status(400).json({
                message: "Forneça os campos obrigatórios e-mail, nova senha, confirme a senha",
                error: true,
                success: false
            })
        }

        const user = await UserModel.findOne({email})

        if(!user){
            return res.status(400).json({
                message: "O e-mail não está disponivel",
                error: true,
                success: false
            })
        }

        if(newPassword !== confirmPassword) {
            return res.status(400).json({
                message: "A nova senha e a confirmação da senha devem ser as mesmas.",
                error: true,
                success: false
            })
        }

        const salt = await bcrypt.genSalt(10)
        const hashPassword = await bcrypt.hash(newPassword,salt)

        const update = await UserModel.findOneAndUpdate(user._id,{
            password : hashPassword
        })

        return res.json({
            message : "Senha atualizada com sucesso.",
            error: false,
            success: true
        })
    }catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}

export async function refreshToken(req, res) {
    try {
        const refreshToken = req.cookies.refreshToken || req?.headers?.authorization?.split(" ")[1]

        if(!refreshToken){
            return res.status(401).json({
                message:"Token inválido",
                error: true,
                success: false
            })
        }

        const verifyToken = await jwt.verify(refreshToken,process.env.SECRET_KEY_REFRESH_TOKEN)

        if(!verifyToken){
            return res.status(401).json({
                message:"O token expirou",
                error: true,
                success: false
            })
        }

        const userId = verifyToken?._id

        const newAccessToken = await generatedAccessToken(userId)

        const cookieOptions = {
            httpOnly : true,
            secure : true,
            sameSite : "None"
        }

        res.cookie('accessToken',newAccessToken,cookieOptions)

        return res.json({
            message : "Novo token de acesso gerado",
            error : false,
            success: true,
            data : {
                accessToken : newAccessToken
            }
        })


    }catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success:false
        })
    }
}