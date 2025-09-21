# IPJ-Election-System

# Sistema de Votação - Igreja Presbiteriana do Jardim

Este projeto é um **sistema de votos online** desenvolvido em Python para auxiliar nas eleições da Igreja Presbiteriana do Jardim. Ele fornece uma interface simples em HTML acessível pelo navegador, onde os membros autorizados podem registrar seus votos de forma organizada.

### Funcionalidades
- Registro de votos para candidatos pré-definidos.
- Interface web simples (HTML + CSS).
- Servidor em Python com Flask.
- Armazenamento temporário em arquivo ou banco de dados leve (SQLite).
- Painel administrativo para verificar resultados.

### Requisitos
- Python 3.8 ou superior
- Git (para clonar o repositório)

### Instalação do Ambiente
1. Clone este repositório:
   ```bash
   git clone https://github.com/AlanVic/IPJ-Election-System.git
   cd IPJ-Election-System
   ```

2. Crie um ambiente virtual:
   ```bash
   python -m venv venv
   ```

3. Ative o ambiente virtual:
   - **Linux/MacOS**:
     ```bash
     source venv/bin/activate
     ```
   - **Windows**:
     ```bash
     venv\Scripts\activate
     ```

4. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

### Executando o Sistema
Para iniciar o servidor local, execute:
```bash
python app.py
```

O sistema rodará por padrão em:
```
http://127.0.0.1:5002
```

Abra o link no navegador e você verá a tela inicial de votação.

### Possíveis Extensões
- Autenticação por CPF/matrícula para validar votantes.
- Integração com banco de dados PostgreSQL/MySQL.
- Relatórios em PDF para secretaria da igreja.
- Deploy em nuvem (Heroku, Railway, etc).  

***

