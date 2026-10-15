FROM python:3.10-slim

WORKDIR /app

COPY ./dist /dist

RUN pip install /dist/omniverse_filesystem_storage_service-*-py3-none-any.whl

ENTRYPOINT ["local-filesystem-service"]
CMD []
