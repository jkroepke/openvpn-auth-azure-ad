FROM python:3.11

WORKDIR /opt/

COPY . .

RUN --mount=source=.git,target=.git,type=bind pip install --no-cache-dir -e .

USER 65534

CMD ["openvpn-auth-azure-ad"]
