# 🔐 Secure Authentication System with Admin Dashboard

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
[![GitHub](https://img.shields.io/badge/GitHub-akilan018--LOGIN--SYSTEM-blue?logo=github)](https://github.com/akilan018/LOGIN-SYSTEM)

A full-stack secure user authentication and management system built using Python (Flask) and MongoDB.

> 🧠 Developed during my internship at **CodeC**.

---

## 🌐 Live Demo  
🚀 **[https://login-system-von4.onrender.com](https://login-system-von4.onrender.com)**  

---

## ✨ Key Features

✅ **Secure User Authentication** – Registration and login with hashed passwords  
✅ **Password Security** – Uses `werkzeug.security` (`pbkdf2_sha256` or `scrypt`) for password hashing  
✅ **JWT-Based Session Management** – Stateless, secure authentication  
✅ **Role-Based Access Control (RBAC)** – Separate privileges for `admin` and `user` roles  
✅ **Admin Dashboard** – Accessible only to Admins via `/admin`  
✅ **User Management** – Admins can view, delete, or reset passwords for users  
✅ **Session Monitoring** – Admin can view and terminate user sessions remotely  
✅ **Forgot Password** – Optional secure password reset feature  

---

## 🧰 Tech Stack

**Backend:**  
- 🐍 Python (Flask)  
- 🗄️ MongoDB  

**Libraries Used:**  
- `flask` – Web framework  
- `flask_pymongo` – MongoDB connection  
- `werkzeug.security` – Password hashing and verification  
- `PyJWT` – JSON Web Tokens  
- `flask_cors` – Cross-origin resource sharing  
- `python-dotenv` – Environment variable management  

**Frontend:**  
- HTML, CSS, JavaScript (via Flask templates)

---

## 🚀 Getting Started

### 🧩 Prerequisites
- Python **3.8+**
- MongoDB (Local or [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register))
- `git` installed on your machine

---

### ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/secure-auth-dashboard.git
   cd secure-auth-dashboard
