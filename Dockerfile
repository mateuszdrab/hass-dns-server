FROM python:3.11-alpine

WORKDIR /app

# Install Python dependencies (add build deps, install, then remove them)
COPY requirements.txt ./
RUN apk add --no-cache --virtual .build-deps build-base libffi-dev openssl-dev libcap \
	&& python_path=$(command -v python || true) \
	&& if [ -n "$python_path" ]; then \
		target=$(readlink -f "$python_path" 2>/dev/null || echo "$python_path"); \
		if [ -f "$target" ]; then setcap cap_net_bind_service=+ep "$target" || true; fi; \
	fi \
	&& pip install --no-cache-dir -r requirements.txt \
	&& apk del .build-deps

# Copy application
COPY dns_server.py ./

# DNS ports (TCP and UDP)
EXPOSE 53 53/udp

# Non-root user (Alpine)
RUN addgroup -S appuser \
	&& adduser -S -G appuser -u 1000 appuser \
	&& chown -R appuser:appuser /app
USER appuser

# Run the server
CMD ["python", "-u", "dns_server.py"]
