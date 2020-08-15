FROM python:3.8

WORKDIR /opt/openvpn-auth-azure-ad/

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

USER 1001

CMD ["/opt/openvpn-auth-azure-ad/openvpn-auth-azure-ad"]
