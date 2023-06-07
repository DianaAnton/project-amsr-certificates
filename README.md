# project-amsr-certificates

## Description

This project was made for university. The  aim is to explore how we can generate X.509 certificates, extend themm, revoke them and create certificate chains.

## How to use

1. Install the requirements from the requirements.txt file using pip.
```bash 
$ pip install -r requirements.txt
```

2. Run the program 
```bash
python3 ./src/main.py
```

---

## Menu functions
### [generate_certificate()](https://github.com/DianaAnton/project-amsr-certificates/blob/f2ab87f0d164a7623ff7da80ee709ee12ed748ea/src/certificate_functions.py#L12)
This takes the following parameters from user input:

| Parameter                 | Type |
|---------------------------|:----:|
| common_name               | str  |
| organization_name         | str  |
| country_name              | str  |
| private_key_path          | str  |
| certificate_path          | str  |
| validity_period           | int  |

 ### [generate_certificate_chain()](https://github.com/DianaAnton/project-amsr-certificates/blob/f2ab87f0d164a7623ff7da80ee709ee12ed748ea/src/certificate_functions.py#L127)

 This will take a certificates_data.json configuration file path from user input. A good example of a file like this can be found [here](#)

| Parameter                     | Type |
|-------------------------------|:----:|
| json_configuration_file_path  | str  |

 ### [read_certificate_data()](https://github.com/DianaAnton/project-amsr-certificates/blob/f2ab87f0d164a7623ff7da80ee709ee12ed748ea/src/certificate_functions.py#L202)

 Takes the path to a certificate that you want to read the data from.

| Parameter                   | Type |
|-----------------------------|:----:|
| certificate_path            | str  |

### [extend_certificate_life()](https://github.com/DianaAnton/project-amsr-certificates/blob/f2ab87f0d164a7623ff7da80ee709ee12ed748ea/src/certificate_functions.py#L225)

Takes the path to the old certificate, the new validity period and the destination of the extended certificate.

| Parameter                   | Type |
|-----------------------------|:----:|
| private_key_path            | str  |
| certificate_path            | str  |
| extended_certificate_path   | str  |
| validity_period             | int  |

### [revoke_certificate()](https://github.com/DianaAnton/project-amsr-certificates/blob/f2ab87f0d164a7623ff7da80ee709ee12ed748ea/src/certificate_functions.py#L295)

The revoke_certificate function revokes a given certificate by performing the following steps:

1. Load the certificate and private key.
2. Check if a Certificate Revocation List (CRL) file exists. If not, create a new one.
3. Set the CRL's last update and next update times to match the certificate's validity period.
4. Add the revoked certificate to the CRL with the specified revocation date.
5. Sign the CRL using the private key and SHA256 hashing algorithm.
6. Serialize and save the updated CRL to a file.
7. Save the revoked certificate separately.

| Parameter                    | Type               |
|------------------------------|:------------------:|
| private_key_path             | str                |
| certificate_path             | str                |
| crl_path                     | str                |
| revoked_cert_path            | str                |
| revocation_date              | datetime.datetime  |