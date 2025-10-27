# To build the container image
```
docker build -t cybersmithio/saml-oidc-test-app:latest  --no-cache .
```

# Publish to Docker hub
```
docker push cybersmithio/saml-oidc-test-app:latest
```

# Run the container
docker run -it  --rm --name saml-oidc-test-app -p 3001:3001 -v ./data:/app/data:ro  cybersmithio/saml-oidc-test-app:latest