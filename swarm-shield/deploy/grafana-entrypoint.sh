#!/bin/bash
set -e

GF_PASSWORD="${GF_SECURITY_ADMIN_PASSWORD:-admin}"
GF_USER="${GF_SECURITY_ADMIN_USER:-admin}"

/run.sh &
GF_PID=$!

for i in $(seq 1 60); do
    if curl -sf http://localhost:3000/api/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if curl -sf http://localhost:3000/api/health >/dev/null 2>&1; then
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

wait $GF_PID
