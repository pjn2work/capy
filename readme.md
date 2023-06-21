# Certificate Authority

### Description

This is a REST API tool to mimic a Certificate Authority that runs on TCP port 25050, 
to generate (Root Certificates, Intermediate Certificates, End-Entity Certificates, Certificate Signing Request).

Every end-point will return a JSON-object



### Git

* Clone project

    ```sh
    $ git clone git@github.com:pjn2work/capy.git
    ```


### Docker

* _If image already exists, and you want to delete it_

    ```sh
    $ docker rm capy
    $ docker rmi -f capy:1.0
    ```

* Goto project folder

    ```sh
    $ cd capy
    ```

* Build docker image

    ```sh
    $ docker build --tag capy:1.0 .
    ```

* Run container

    ```sh
    $ docker run -p 25050:25050 --name capy capy:1.0
    ```


### How to use

##### 1. Web access

* **http://localhost:25050/ca**

<br/>

##### 2. REST API

| method | end-point                                | parameters                                    | body                                | action                               | output (json)                        |
| ------ | :--------------------------------------- | :-------------------------------------------- | :---------------------------------- | :----------------------------------- |:-------------------------------------|
| GET    | http://localhost:25050/ca/gen-csr         | CN, O, OU, C, ST, L                           |                                     | Generate a CSR                       | type, data, private_key, public_key  |
| GET    | http://localhost:25050/ca/gen-cert-root   | CN, O, OU, C, ST, L,<br/>days, path_length    |                                     | Generate a root certificate          | type, data, private_key, public_key | 
| POST   | http://localhost:25050/ca/gen-cert-interm |   | CN, O, OU, C, ST, L,<br/>days, path_length,<br/>issuer_private_key, issuer_cert | Generate an intermediate certificate | type, data, private_key, public_key  |
| POST   | http://localhost:25050/ca/gen-cert-end    |   | issuer_private_key, issuer_cert, csr_data                                       | Generate an end-entity certificate   | type, data                           |
