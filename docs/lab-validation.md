# Sentinel isolated validation laboratory

The lab is for deliberately vulnerable training applications only. Its services
bind to loopback and must not be exposed to a LAN, public interface, tunnel, or
shared production network.

## Start and stop

Review image digests before every update, then run:

```bash
docker compose -f deploy/lab/compose.yaml pull
docker image inspect bkimminich/juice-shop:v20.2.0 --format '{{json .RepoDigests}}'
docker image inspect webgoat/webgoat:v2026.4 --format '{{json .RepoDigests}}'
docker compose -f deploy/lab/compose.yaml up -d
docker compose -f deploy/lab/compose.yaml ps
```

Open Juice Shop at `http://127.0.0.1:3000`, WebGoat at
`http://127.0.0.1:18080/WebGoat`, and WebWolf at
`http://127.0.0.1:19090/WebWolf`.

Create a lab engagement:

```bash
python3 sentinel.py engagement create sentinel-lab \
  --domain localhost --ip 127.0.0.1/32 \
  --enable-active --lab-mode --max-rate 10
```

Stop and remove the disposable applications after validation:

```bash
docker compose -f deploy/lab/compose.yaml down --volumes --remove-orphans
```

Never reuse lab accounts, tokens, data, or findings in a real engagement.
Record the application image digest, Sentinel commit, tool certification, test
case, expected result, observed result, request count, duration, false-positive
decision, cleanup result, and evidence hash for every benchmark.
