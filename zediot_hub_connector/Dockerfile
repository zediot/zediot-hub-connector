ARG BUILD_FROM
FROM ${BUILD_FROM}

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir /app

COPY zediot_hub_connector/run.sh /run.sh
RUN chmod 0755 /run.sh

CMD ["/run.sh"]
