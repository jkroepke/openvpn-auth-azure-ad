FROM python:3.10

WORKDIR /opt/

COPY . .

RUN --mount=source=.git,target=.git,type=bind pip install --no-cache-dir -e .

USER 1001

CMD ["openvpn-auth-azure-ad"]
