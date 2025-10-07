# Cardea SSH Bastion Server

Cardea is an SSH bastion server that provides access control and session recording for connections to backend servers. It acts as a proxy, authenticating clients and forwarding connections to authorized backend servers based on configurable rules.

## Architecture

### Connection flow

1. The client connects to the bastion, encoding the backend server in the SSH username ([see below](#client-connection)).
2. The bastion validates the client's public key against the authorized keys.
3. Access rules are checked against the requested backend server.
4. If authorized, the bastion establishes a connection to the backend server using its own key.
5. The session is proxied with optional recording in [asciinema v3](https://www.asciinema.org) format compressed with gzip.

> [!NOTE]
> The bastion's public key must be added to the authorized keys of the backend servers it connects to. This is necessary for the bastion to authenticate itself to the backend servers. You can use the [`from` option](https://man.openbsd.org/sshd#from=_pattern-list_) in the backend server's `authorized_keys` file to restrict access to the bastion's public key.

## Installation

### Using Docker

Available in the [GitHub Container Registry](https://github.com/hectorm/cardea/pkgs/container/cardea) and [Docker Hub](https://hub.docker.com/r/hectorm/cardea).

```sh
docker run -p '2222:2222' -u "$(id -u):$(id -g)" --mount 'type=bind,src=./data/,dst=/data/' ghcr.io/hectorm/cardea:v1
```

### Prebuilt binaries

Download prebuilt binaries from the [releases page](https://github.com/hectorm/cardea/releases) for your platform.

## Configuration

### Command-line options

```
-listen string
      address to listen on (env CARDEA_LISTEN) (default ":2222")
-private-key-file string
      path to the host private key (env CARDEA_PRIVATE_KEY_FILE) (default "/etc/cardea/private_key")
-private-key-passphrase string
      passphrase for the private key (env CARDEA_PRIVATE_KEY_PASSPHRASE)
-private-key-passphrase-file string
      path to file containing the private key passphrase (env CARDEA_PRIVATE_KEY_PASSPHRASE_FILE)
-authorized-keys-file string
      path to the authorized keys file (env CARDEA_AUTHORIZED_KEYS_FILE) (default "/etc/cardea/authorized_keys")
-known-hosts-file string
      path to the known hosts file (env CARDEA_KNOWN_HOSTS_FILE) (default "/etc/cardea/known_hosts")
-unknown-hosts-policy string
      policy for unknown hosts: strict (deny unknown), tofu (trust on first use) (env CARDEA_UNKNOWN_HOSTS_POLICY) (default "strict")
-connections-max int
      maximum number of concurrent connections; 0 for unlimited (env CARDEA_CONNECTIONS_MAX) (default 1000)
-rate-limit-max int
      maximum number of unauthenticated requests per IP address; 0 for unlimited (env CARDEA_RATE_LIMIT_MAX) (default 10)
-rate-limit-time duration
      time window for rate limiting unauthenticated requests (env CARDEA_RATE_LIMIT_TIME) (default 5m0s)
-recordings-dir string
      directory to store session recordings; disabled if empty (env CARDEA_RECORDINGS_DIR)
-recordings-retention-time duration
      time to retain session recordings (env CARDEA_RECORDINGS_RETENTION_TIME) (default 720h0m0s)
-recordings-max-disk-usage string
      maximum disk usage for session recordings; accepts percentage (e.g. 90%) or fixed size (e.g. 1GB) (env CARDEA_RECORDINGS_MAX_DISK_USAGE) (default "90%")
-log-level string
      log level: debug, info, warn, error, quiet (env CARDEA_LOG_LEVEL) (default "info")
-version
      show version and exit
```

### Authorized keys format

Cardea uses a variation of the SSH authorized keys format to define access rules and options for each key.

```sh
permitconnect="user1@host1:port1,user2@host2:port2",permitopen="host1:port1,host2:port2",command="cmd",no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
```

#### Required

- **`permitconnect`**: comma-separated list of allowed backend server connections (can be specified multiple times).
  - **Format:** `<user>@<host>[:<port>]` or `<user>+<host>[+<port>]`.
  - Supports glob patterns (defined by the [Go `filepath.Match` function](https://pkg.go.dev/path/filepath#Match)) for users.
  - Supports glob patterns and CIDR blocks for hosts.
  - Supports glob patterns and ranges (e.g., `8000-8999`) for ports.
  - If no port is specified, the default SSH port (22) is used.
  - If multiple `permitconnect` options for the same public key are present, the first match is used and the options specified in that match are applied.
  - **Example:** `permitconnect="alice@*.internal,alice@10.0.1.1/16"`.

#### Optional

- **`permitopen`**: comma-separated list of allowed port forwarding destinations (can be specified multiple times).
  - **Format:** `<host>:<port>`.
  - Supports glob patterns and CIDR blocks for hosts.
  - Supports glob patterns and ranges (e.g., `8000-8999`) for ports.
  - By default, only localhost traffic to any port is allowed.
  - **Example:** `permitopen="localhost:1-65535,127.0.0.1/8:1-65535,[::1/128]:1-65535"`.
- **`command`**: force execution of a specific command.
  - **Example:** `command="nologin"`.
- **`no-pty`**: disable pseudo-terminal allocation.
- **`no-port-forwarding`**: disable port forwarding.

#### Macro support

It is possible to use the `#define` directive to define reusable fragments. Macros are simple text substitutions that can be used anywhere in the authorized_keys file.

```sh
#define ALICE_PUBKEY ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
#define BOB_PUBKEY ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...

#define SERVER_DEV op@dev.example.com,op@10.0.1.1
permitconnect="SERVER_DEV" ALICE_PUBKEY
permitconnect="SERVER_DEV" BOB_PUBKEY

#define SERVER_STAGING op@staging.example.com,op@10.0.2.1
permitconnect="SERVER_STAGING" ALICE_PUBKEY
permitconnect="SERVER_STAGING" BOB_PUBKEY
```

### Client connection

To connect, clients specify the backend server they wish to access as part of the SSH username. The following formats are supported:

```sh
# Using @ and : as delimiters
ssh -p <bastion-port> <user>@<host>[:<port>]@<bastion-host>
ssh -p <bastion-port> -o User=<user>@<host>[:<port>] <bastion-host>

# Using + as delimiter (to avoid ambiguity with the @ used by SSH)
ssh -p <bastion-port> <user>+<host>[+<port>]@<bastion-host>
ssh -p <bastion-port> -o User=<user>+<host>[+<port>] <bastion-host>
```

#### Examples

```sh
ssh -p 2222 alice@10.0.1.1@cardea.internal
ssh -p 2222 -o User=alice@10.0.1.1 cardea.internal

ssh -p 2222 alice+10.0.1.1@cardea.internal
ssh -p 2222 -o User=alice+10.0.1.1 cardea.internal

# Using an SSH config file
cat >> ~/.ssh/config <<-'EOF'
Host backend
    HostName cardea.internal
    Port 2222
    User alice@10.0.1.1
EOF
ssh backend

# Using sftp
sftp -P 2222 alice+10.0.1.1@cardea.internal
sftp -P 2222 -o User=alice@10.0.1.1 cardea.internal

# Using rsync
rsync -ave 'ssh -p 2222' alice+10.0.1.1@cardea.internal:/remote/dir/ /local/dir/
rsync -ave 'ssh -p 2222 -o User=alice@10.0.1.1' cardea.internal:/remote/dir/ /local/dir/
```

## License

[EUPL-v1.2-or-later](./LICENSE) © [Héctor Molinero Fernández](https://hector.molinero.dev).
