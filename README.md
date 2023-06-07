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
### [generate_certificate()](#)
This takes the following parameters from user input:

| Parameter                 | Type |
|---------------------------|:----:|
| common_name               | str  |
| organization_name         | str  |
| country_name              | str  |
| private_key_path          | str  |
| certificate_path          | str  |
| validity_period           | int  |

 ### [generate_certificate_chain()](#)

 This will take a certificates_data.json configuration file path from user input. A good example of a file like this can be found [here](#)

| Parameter                     | Type |
|-------------------------------|:----:|
| json_configuration_file_path  | str  |

 ### [read_certificate_data()](#)

 Takes the path to a certificate that you want to read the data from.

| Parameter                   | Type |
|-----------------------------|:----:|
| certificate_path            | str  |

### [extend_certificate_life()](#)

Takes the path to the old certificate, the new validity period and the destination of the extended certificate.

| Parameter                   | Type |
|-----------------------------|:----:|
| private_key_path            | str  |
| certificate_path            | str  |
| extended_certificate_path   | str  |
| validity_period             | int  |

### [revoke_certificate()](#)

Takes the path to the old certificate, the new validity period and the destination of the extended certificate.

| Parameter                    | Type |
|------------------------------|:----:|
| private_key_path             | str  |
| certificate_path             | str  |
| crl_path                     | str  |
| revoked_cert_pat             | str  |
| revocation_month             | int  |
| revocation_day               | int  |
| revocation_year              | int  |