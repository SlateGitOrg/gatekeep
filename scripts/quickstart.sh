#!/usr/bin/env bash
# Prepare a local, real-process gatekeep setup in ./.gatekeep (gitignored):
# self-signed TLS cert, secrets, device key, upstream key, configs and
# password hashes. Then prints the commands to run in separate terminals.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=.gatekeep
mkdir -p "$OUT/devices" bin
go build -o bin/ ./cmd/...

./bin/gatekeep dev-cert --hosts 127.0.0.1,localhost --cert "$OUT/tls.crt" --key "$OUT/tls.key" --days 7
./bin/posture-agent keygen --out "$OUT/alice-laptop.key" | grep -v '^#' > "$OUT/devices/alice-laptop.pub.pem"
./bin/gatekeep keygen --alg ES256 --out "$OUT/upstream.key" > /dev/null

cp examples/gatekeep.yaml "$OUT/gatekeep.yaml"
cp examples/facts/compliant.json "$OUT/facts.json"
sed_inplace() { if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi; }
cp examples/idp.yaml "$OUT/idp.yaml"
for u in alice bob carol; do
  h=$(printf '%s-pw\n' "$u" | ./bin/gatekeep-idp hash-password)
  U=$(echo "$u" | tr '[:lower:]' '[:upper:]')
  sed_inplace "s|${U}_HASH|${h//|/\\|}|" "$OUT/idp.yaml"
done

cat > "$OUT/env" <<ENV
export GATEKEEP_CLIENT_SECRET=$(./bin/gatekeep secret)
export GATEKEEP_SESSION_SECRETS=$(./bin/gatekeep secret)
ENV
chmod 600 "$OUT/env"
./bin/gatekeep check --config "$OUT/gatekeep.yaml"

cat <<MSG

Ready. In four terminals (from the repo root):
  1) source $OUT/env && ./bin/gatekeep-idp serve --config $OUT/idp.yaml
  2) ./bin/gatekeep-demo -upstream 127.0.0.1:9000 -gatekeep https://127.0.0.1:8443 -ca $OUT/tls.crt
  3) source $OUT/env && ./bin/gatekeep serve --config $OUT/gatekeep.yaml
  4) open https://127.0.0.1:8443/wiki/ (accept the self-signed cert; log in as alice / alice-pw),
     then visit https://127.0.0.1:8443/.gatekeep/device, press "Pair a device" and run:
     ./bin/posture-agent pair --proxy https://127.0.0.1:8443 --code <CODE> --device-id alice-laptop \\
         --key $OUT/alice-laptop.key --facts $OUT/facts.json --ca $OUT/tls.crt
     Now https://127.0.0.1:8443/admin/ is reachable. Audit log: $OUT/audit.jsonl
MSG
