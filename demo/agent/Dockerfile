FROM python:3.11-slim
WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi uvicorn httpx anthropic openai cryptography pyjwt jinja2 \
    websockets python-multipart

# Install cullis_sdk from the project
COPY cullis_sdk/ ./cullis_sdk/
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

# Copy the agent console app
COPY demo/agent/app.py ./agent_app.py
COPY demo/agent/templates/ ./templates/

EXPOSE 8080
CMD ["uvicorn", "agent_app:app", "--host", "0.0.0.0", "--port", "8080"]
