MySQL (Docker) quick start for securechat-skeleton

This guide shows how to run a MySQL server in Docker for the assignment and
initialize the database used by `app/storage/db.py`.

1) Pull and run MySQL container

```bash
# Pull official image (adjust version as desired)
docker pull mysql:8.0

# Run container with root password, mapped port 3306
docker run -d --name securechat-mysql -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_DATABASE=securechat -p 3306:3306 mysql:8.0
```

Notes:
- `MYSQL_ROOT_PASSWORD` sets the root password (use a stronger password in real use).
- `MYSQL_DATABASE` creates the database `securechat` which the app expects by default.

2) (Optional) Create a dedicated user

```bash
# Exec into container and use mysql CLI
docker exec -it securechat-mysql mysql -uroot -prootpass
show databases;
use securechat;
select * from users;

```

3) Configure the application (env vars)

The `app/storage/db.py` defaults to connecting to:
- host: 127.0.0.1
- port: 3306
- user: root
- password: (empty)
- database: securechat

You can set environment variables to match your container:
- MYSQL_HOST (default 127.0.0.1)
- MYSQL_PORT (default 3306)
- MYSQL_USER (default root)
- MYSQL_PASSWORD
- MYSQL_DATABASE (default securechat)

Example (use dedicated user):

```bash
export MYSQL_HOST=127.0.0.1
export MYSQL_PORT=3306
export MYSQL_USER=sc_user
export MYSQL_PASSWORD=sc_pass
export MYSQL_DATABASE=securechat
```

4) Initialize schema (server will call this automatically on first connection)

`UserDB.init_schema()` is called by the server when handling a connection. You can also initialize manually from the host:

```bash
# Run the provided SQL via mysql client
docker exec -i securechat-mysql mysql -uroot -prootpass securechat < <(cat <<'SQL'
CREATE TABLE IF NOT EXISTS users (
  email VARCHAR(255),
  username VARCHAR(255) UNIQUE,
  salt VARBINARY(16),
  pwd_hash CHAR(64),
  PRIMARY KEY (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL
)
```

5) Run the server and client

Start the Python server in the workspace (adjust env vars as needed):

```bash
# from project root
export MYSQL_USER=sc_user
export MYSQL_PASSWORD=sc_pass
python3 app/server.py
```

In another shell, run the client and follow prompts:

```bash
python3 app/client.py
```

You can automate registration with environment vars before running the client:

```bash
export ACTION=register
export REG_EMAIL=test@example.com
export REG_USERNAME=testuser
export REG_PWD=MySecretPass
python3 app/client.py
```

Or login:

```bash
export ACTION=login
export REG_EMAIL=test@example.com
export REG_PWD=MySecretPass
python3 app/client.py
```

Security notes
- This setup is for assignment/testing only. Use secure passwords and network restrictions for real deployments.
- The application transmits credentials only over the ephemeral AES channel derived from DH and requires certificate validation.

*** End of guide ***
