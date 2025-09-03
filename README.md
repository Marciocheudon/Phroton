# Phroton

**Phroton** é um projeto de pesquisa em cibersegurança utilizando inteligência artificial, desenvolvido por **MarcioCheudon**.  

O sistema realiza **detecção de ameaças via IA**: basta fornecer a URL da aplicação web a ser analisada e o modelo examinará arquivo por arquivo, retornando possíveis vulnerabilidades encontradas e que podem ser exploradas.  
Este projeto **não substitui** a exploração manual ou a análise de um especialista em segurança.  

> **Aviso**: Deve ser utilizado apenas para fins educativos. O criador **Marciocheudon** se isenta de qualquer responsabilidade por uso indevido do mesmo.

## Funcionalidades

- Análise automatizada de padrões de ameaça usando modelos de LLM, como o **Qwen2.5-Coder**.  
- Exportação das vulnerabilidades detectadas em formato de relatório.  

## Tecnologias

- **Linguagem**: Python  
- **Ferramentas**: [Ollama](https://ollama.com) (execução local de modelos LLM)  

## Instalação

# 1. Clone o repositório
git clone https://github.com/Marciocheudon/Phroton.git
cd Phroton

# 2. Instale dependências
pip install -r requirements.txt

## Uso

# 1. Execute o serviço de analise
python main.py https://loveblou.app

## Contribuição

Contribuições são bem-vindas. Para colaborar:

1. Faça um **fork** do repositório
2. Crie uma nova branch:

   git checkout -b feature/minha-contribuicao

3. Faça commits claros e objetivos
4. Envie um **Pull Request** explicando o objetivo e as mudanças realizadas
5. Aguarde revisão e feedback

## Licença

Este projeto está licenciado sob a **MIT License**.
