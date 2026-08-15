#!/bin/bash
set +e

GF_PASSWORD="${GF_SECURITY_ADMIN_PASSWORD:-admin}"
GF_USER="${GF_SECURITY_ADMIN_USER:-admin}"

if [ -f /run.sh ]; then
    /run.sh "$@" &
elif command -v grafana-server >/dev/null 2>&1; then
    grafana-server \
        --homepath=/usr/share/grafana \
        --config=/etc/grafana/grafana.ini \
        --packaging=docker \
        "$@" &
else
    echo "ERROR: Cannot find grafana-server or /run.sh" >&2
    exit 1
fi

GF_PID=$!

for i in $(seq 1 90); do
    if (echo > /dev/tcp/127.0.0.1/3000) 2>/dev/null; then
        break
    fi
    if ! kill -0 "$GF_PID" 2>/dev/null; then
        wait "$GF_PID" || true
        exit 0
    fi
    sleep 1
done

if (echo > /dev/tcp/127.0.0.1/3000) 2>/dev/null; then
    if command -v grafana-cli >/dev/null 2>&1; then
        grafana-cli admin reset-admin-password "${GF_PASSWORD}" >/dev/null 2>&1 || true
    elif command -v curl >/dev/null 2>&1; then
        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"${GF_USER}\",\"password\":\"${GF_PASSWORD}\"}" \
            http://localhost:3000/api/login 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ]; then
            CSRF=$(curl -s http://localhost:3000/api/login | grep -o '"csrfToken":"[^"]*"' | cut -d'"' -f4 || echo "")
            if [ -n "$CSRF" ]; then
                curl -s -X PUT \
                    -H "Content-Type: application/json" \
                    -H "X-Grafana-URL: http://localhost:3000" \
                    -H "X-Grafana-CSRF-Token: ${CSRF}" \
                    -d "{\"password\":\"${GF_PASSWORD}\"}" \
                    http://localhost:3000/api/admin/users/current/password >/dev/null 2>&1 || true
            fi
        fi
    fi
fi

wait "$GF_PID"
