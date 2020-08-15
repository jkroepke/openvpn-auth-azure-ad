FROM python:3.8

WORKDIR /opt/

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

USER 1001

CMD ["/opt/openvpn_auth_azure_ad/openvpn-auth-azure-ad"]
