FROM python:3.8

WORKDIR /opt/openvpn_aad_authenticator/

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

USER 1001

CMD ["/opt/openvpn_aad_authenticator/openvpn_aad_authenticator"]
