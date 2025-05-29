# Passwordless Authentication System Using TKey 

A secure, passwordless authentication system using TKey hardware device.

## Table of Contents
- [✨ Features](#-features)
- [🛠️ Technologies Used](#️-technologies-used)
- [🚀 Installation](#-installation)
- [🙏 Acknowledgements](#-acknowledgements)

## ✨ Features
- **🔑 Passwordless Authentication** - TKey hardware-based authentication
- **🛡️ Two-Factor Authentication** - TOTP for extra security
- **🔓 Secure Account Recovery** - Mnemonic phrase-based
- **🤝 Challenge-Response Protocol** - Cryptographic verification

## 🛠️ Technologies Used

### Backend
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)

### Database
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)

### Frontend
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)

### Infrastructure
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)



## 🚀 Installation

### Prerequisites
- [Go 1.20+](https://go.dev/dl/)
- [Python 3.10+](https://www.python.org/downloads/)
- [Docker](https://docs.docker.com/get-docker/)
- [TKey Device](https://tillitis.se/)

### Setup
Clone the repository:
```bash
git clone https://github.com/SkepparAbbe/TKey-group-95.git
cd TKey-group-95
```

## ⚡ Usage

### Running the Proxy Server
```bash
cd Proxy-server/tkey/
go run main.go
```

### Running the Web Application 🐳
```bash
cd Web-application/
docker compose up 
```
### Stopping Containers
```bash
docker compose down
```
### ♻️ Reset Docker Environment (optional)

> **⚠️ Warning:** This will permanently delete all Docker containers, volumes, and database data!

**1. Stop and remove all containers, networks, and volumes:**
```bash
docker compose down -v
```

**2. Clean up all unused containers, images, and volumes:**
```bash
docker system prune -a --volumes -f
```

### Accessing Services
- Web Application: `http://localhost:5000`
- PostgreSQL: `port 5432`
- Redis: `port 6379`

## 🙏 Acknowledgements
- Tillitis AB for the TKey hardware and TKey related libraries
