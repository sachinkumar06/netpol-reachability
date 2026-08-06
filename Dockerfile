FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --target /install .

FROM python:3.12-slim
COPY --from=build /install /usr/local/lib/python3.12/site-packages
COPY examples /examples
ENV PYTHONPATH=/usr/local/lib/python3.12/site-packages
RUN useradd --create-home --uid 10001 app
USER 10001
ENTRYPOINT ["python", "-m", "netpol_reachability"]
CMD ["graph", "-f", "/examples/demo-cluster"]
