FROM python:3.11.7

WORKDIR /

COPY ./srcs /

RUN chmod +x launch.sh

RUN pip install --root-user-action=ignore --no-cache-dir --upgrade pip \
    && pip install --root-user-action=ignore --no-cache-dir -r requirements.txt \
    && pip install --root-user-action=ignore --no-cache-dir psycopg2-binary \
    && mkdir -p /app/staticfiles

EXPOSE 8080

CMD ["./launch.sh"]
