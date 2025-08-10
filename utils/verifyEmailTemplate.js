const verifyEmailTemplate = ({ name, url }) => {
    return `
    <p>Prezado(a) ${name},</p>
    <p>Obrigado por se cadastrar na Angelluci Cosméticos.</p>
    <a href="${url}" style="color: black; background: orange; margin-top: 10px; padding: 20px; display: inline-block;">
        Verificar E-mail
    </a>
    `;
};

export default verifyEmailTemplate;