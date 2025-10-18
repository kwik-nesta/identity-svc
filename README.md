![Docker Image Version](https://img.shields.io/docker/v/blueclikk/kwik-nesta.identity.svc?sort=semver&label=version)
![Docker Pulls](https://img.shields.io/docker/pulls/blueclikk/kwik-nesta.identity.svc)

### 🔐 Kwik Nesta Identity Service

The **Identity Service** is a core microservice responsible for authentication and authorization in the Kwik Nesta platform. It provides secure user management for **Tenants, Landlords, Administrators, and Superadmins**, ensuring role-based access control across the ecosystem.

#### ✨ Features

* User registration & login (JWT-based authentication)
* Role-based access (Tenant, Landlord, Admin, SuperAdmin)
* Refresh token support
* Secure password hashing & validation
* Integration with external identity providers (future-ready)
* Extensible design for multi-service authentication

#### 🛠️ Tech Stack

* **.NET 8** (ASP.NET Core Web API)
* **Entity Framework Core**
* **SQL Server** (configurable)
* **RabbitMQ** (for async messaging, e.g., user events)
* **OpenTelemetry** for observability (metrics, logs, traces)

#### 📦 Usage

This service is designed to be consumed by other Kwik Nesta microservices and clients.
Typical workflow:

1. Register or sign in a user
2. Obtain JWT + Refresh Token
3. Use JWT to access secured endpoints across the platform
4. Identity service validates and authorizes based on roles/claims

#### 🚀 Roadmap

* Multi-factor authentication (MFA)
* Social login (Google, Facebook, etc.)
* Audit trails for login activities
* Integration with centralized API Gateway