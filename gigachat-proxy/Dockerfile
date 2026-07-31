# gpt2giga — официальный (Sber) OpenAI-совместимый прокси к GigaChat.
# Берёт на себя OAuth Sber, обновление токена и российский TLS.
# Учётные данные читаются gigachat-SDK из env: GIGACHAT_CREDENTIALS, GIGACHAT_SCOPE.
FROM python:3.12-slim
RUN pip install --no-cache-dir gpt2giga
EXPOSE 8090
# pass-model=true — пробрасывать имя модели (GigaChat/-Pro/-Max) как есть.
CMD ["gpt2giga", \
     "--proxy.host", "0.0.0.0", "--proxy.port", "8090", \
     "--proxy.pass-model", "true", \
     "--gigachat.verify-ssl-certs", "false"]
