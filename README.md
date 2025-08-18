E-commerce Backend
Este é o backend da aplicação de E-commerce, desenvolvido com Node.js, Express e MongoDB.

Pré-requisitos
Antes de começar, certifique-se de ter o seguinte software instalado em seu computador:

Node.js: Download

npm (gerenciador de pacotes do Node.js): Geralmente vem junto com a instalação do Node.js.

MongoDB: Você pode usar uma instância local (instalando-o em sua máquina) ou um serviço em nuvem como o MongoDB Atlas.

VS Code (ou seu editor de código preferido): Download

Instalação e Configuração
Siga os passos abaixo para clonar o repositório, instalar as dependências e configurar o ambiente de desenvolvimento.

1. Clonar o Repositório
Abra o seu terminal (VScode) e clone o repositório para o seu computador:

git clone https://github.com/BlackJVictor/Ecommerce.git

2. Navegar para a Pasta do Backend
Após clonar o repositório, entre na pasta do projeto e na subpasta do backend:

cd Ecommerce/server

3. Instalar as Dependências
Com o terminal dentro da pasta server, instale todas as dependências do projeto listadas no arquivo package.json usando o npm:

npm install express cors mongoose jsonwebtoken bcryptjson cookie-parse dotenv morgan helmet multer resend

4. Configurar Variáveis de Ambiente
Este projeto usa variáveis de ambiente para gerenciar informações sensíveis, como chaves de acesso e a URL de conexão com o banco de dados.

Crie um arquivo chamado .env na raiz da pasta server e adicione as seguintes variáveis:

FRONTEND_URL = "http://localhost:8080/3000"
MONGODB_URI = 
RESEND_API = 
SECRET_KEY_ACCESS_TOKEN = 
SECRET_KEY_REFRESH_TOKEN = 
CLOUDINARY_CLOUD_NAME = 
CLOUDINARY_API_KEY = 
CLOUDINARY_API_SECRET_KEY = 

Observação: Insere com suas próprias informações. Mantenha este arquivo em segredo e nunca o envie para o GitHub.

Como Executar o Projeto
Para iniciar o servidor de desenvolvimento, execute o seguinte comando no terminal (dentro da pasta server):

npm run dev
