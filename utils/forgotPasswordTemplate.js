const forgotPasswordTemplate = ({ name, otp })=>{
    return `
<div>
    <p>Prezado, ${name}</p>
    <p>Você foi solicitado a redefinir sua senha. Use o seguinte código OTP para redefinir sua senha.</p>
    <div style="background: yellow; font-size:20px;padding:20px;text-align:center;font-weigth : 800;">
    ${otp}
    </div>
    <p>Este otp é valido por apenas 1 hora. Insira este otp no site Angelucci para prosseguir com a definição de senha</p>
    <br>
    <br>
    <p>Obrigado</p>
    <p>Angelucci Cosméticos</p>     `
}

export default forgotPasswordTemplate