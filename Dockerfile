FROM python:3.8
WORKDIR /opt/openvpn_aad_authenticator/

RUN sed -i 's/psycopg2-binary/psycopg2/' requirements.txt \
   && pip install --no-cache-dir -r requirements.txt \
   && chgrp -R 0 . && chmod g=u -R . \
   && chmod g=u /etc/passwd

COPY docker/root/ /

COPY handlers.py .
COPY lib lib

USER 1001

CMD ["/opt/openvpn_aad_authenticator/openvpn_aad_authenticator"]
