# FusionAuth golang microservices example

This code is an example of protecting golang microservices with JSON web tokens.

## To run

This assumes you already have go 1.15.8 installed and have cloned this repo.

In one terminal:
* cd jwt_client
* go get
* go run main.go

In another terminal:
* cd api_gateway
* go get
* go run main.go

In yet another terminal:

* curl http://localhost:8080 # to get the JWT
* curl http://localhost:9001 --header 'Token: [jwt value]' # to get the secret microservice response

Original code by @krissnawat
