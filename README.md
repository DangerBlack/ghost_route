# Ghost Route

```sh
 _____ _     ____  ____ _____    ____  ____  _    _____ _____
/  __// \ /|/  _ \/ ___Y__ __\  /  __\/  _ \/ \ /Y__ __Y  __/
| |  _| |_||| / \||    \ / \    |  \/|| / \|| | || / \ |  \  
| |_//| | ||| \_/|\___ | | |    |    /| \_/|| \_/| | | |  /_ 
\____\\_/ \|\____/\____/ \_/    \_/\_\\____/\____/ \_/ \____\
```

Ghost Route is a minimal, encrypted URL shortener and proxy server written in Go. It allows you to generate encrypted, links that proxy content from allowed hosts, providing privacy and access control for shared URLs.

## Features

- AES-256-GCM encryption for URLs
- Only allows proxying to whitelisted hosts
- Generates short, encrypted links
- Simple REST API
- Lightweight and easy to deploy (Docker-ready)

## Usage

### 1. Configuration

Create a `.env` file in the project root:

```
AES_KEY=your_base64_32byte_key
ALLOWED_HOSTS="example.com,another.com,localhost:8080"
PORT=8080
```

- `AES_KEY`: Base64-encoded 32-byte key (use `openssl rand -base64 32`)
- `ALLOWED_HOSTS`: Comma-separated list of allowed hostnames (no protocol)
- `PORT`: Port to run the server (default: 8080)

### 2. Running Locally

```bash
go run main.go
```

### 3. Using Docker

Build and run with Docker:

```bash
docker build -t ghost_route .
docker run --env-file .env -p 8080:8080 ghost_route
```

### 4. API

#### Shorten a URL

```bash
POST /shorten?url={target_url}
```

- Returns: `{ "link": "http://<host>/<encrypted>" }`

#### Proxy a Link

```bash
GET /{encrypted}
```

- Streams the content from the original URL if the host is allowed.

## Security Notes

- Only hosts listed in `ALLOWED_HOSTS` are accessible.
- The encryption key must be kept secret.

## License

MIT
