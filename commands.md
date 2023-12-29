python -m venv venv
source venv/Scripts/activate
pip install --upgrade pip
pip install fastapi
pip install "python-jose[cryptography]"

openssl rand -hex 32
oathtool --totp --base32

uvicorn main:app --port 8000

./run-docker-compose.sh 
docker-compose -f compose.yaml up