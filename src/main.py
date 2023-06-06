# import the certificate_fucntions.py file
from certificate_functions import (
    generate_certificate,
    generate_certificate_chain,
    extend_certificate_life,
    revoke_certificate,
    read_certificate_data,
)
import json, datetime

# declare the main function


def main():
    # create a menu for the user to select from
    print("1. Generate a self-signed certificate")
    print("2. Generate a certificate chain")
    print("3. Extend the life of a certificate")
    print("4. Revoke a certificate")
    print("5. Read certificate data")
    print("6. Exit")
    # take the user input
    choice = int(input("Enter your choice: "))
    # if the user enters 1
    if choice == 1:
        # # take the user input for the common name
        # common_name = input('Enter the common name: ')
        # # take the user input for the organization name
        # organization_name = input('Enter the organization name: ')
        # # take the user input for the country name
        # country_name = input('Enter the country name: ')
        # # take the user input for the private key path
        # private_key_path = input('Enter the private key path: ')
        # # take the user input for the certificate path
        # certificate_path = input('Enter the certificate path: ')
        # # take the user input for the validity period
        # validity_period = int(input('Enter the validity period in days: '))

        common_name = "root"
        organization_name = "uvt"
        country_name = "ro"
        private_key_path = "./certs/root_private_key_1.pem"
        certificate_path = "./certs/root_certificate_1.pem"
        validity_period = 365

        # print all the values
        print("Common name: " + common_name)
        print("Organization name: " + organization_name)
        print("Country name: " + country_name)
        print("Private key path: " + private_key_path)
        print("Certificate path: " + certificate_path)
        print("Validity period: " + str(validity_period))

        # generate a self-signed certificate
        generate_certificate(
            common_name,
            organization_name,
            country_name,
            private_key_path,
            certificate_path,
            validity_period,
        )
    # if the user enters 2
    elif choice == 2:
        # # get the user input for the path of the json configuration file
        # json_configuration_file_path = input(
        #     "Enter the path of the json configuration file: "
        # )
        json_configuration_file_path = "./certificate_chain/certificates_data.json"
        # print the path of the json configuration file
        print("Json configuration file path: " + json_configuration_file_path)

        # load the json configuration file using the json module
        with open(json_configuration_file_path) as json_file:
            certificates_data = json.load(json_file)

        # generate a certificate chain
        generate_certificate_chain(certificates_data)
    # if the user enters 3
    elif choice == 3:
        # # take the user input for the certificate path
        # certificate_path = input("Enter the certificate path: ")
        # # take the user input for the private key path
        # private_key_path = input("Enter the private key path: ")
        # # take the user input for the extended certificate path
        # extended_certificate_path = input(
        #     "Enter the extended certificate path: ")
        # # take the user input for the validity days
        # validity_days = int(input("Enter the validity days: "))
        # generate some test values to be hardcoded
        certificate_path = './certs/root_certificate_1.pem'
        private_key_path = './certs/root_private_key_1.pem'
        extended_certificate_path = './certs/extended_root_certificate_1.pem'
        validity_days = 665

        # print all the values
        print("Certificate path: " + certificate_path)
        print("Private key path: " + private_key_path)
        print("Extended certificate path: " + extended_certificate_path)
        print("Validity days: " + str(validity_days))

        # extend the life of the certificate
        extend_certificate_life(certificate_path, private_key_path, extended_certificate_path, validity_days)
    # if the user enters 4
    elif choice == 4:
        # # take the user input for the certificate path
        # certificate_path = input("Enter the certificate path: ")
        # # take the user input for the private key path
        # private_key_path = input("Enter the private key path: ")
        # # take the user input for the crl path
        # crl_path = input("Enter the crl path: ")
        # # take the user input for the revoked certificate path
        # revoked_cert_path = input("Enter the revoked certificate path: ")
        # take the user input for the revocation year
        # revocation_year = int(input("Enter the revocation year: "))
        # take the user input for the revocation month
        # revocation_month = int(input("Enter the revocation month: "))
        # take the user input for the revocation day
        # revocation_day = int(input("Enter the revocation day: "))
        # convert the revocation date to a datetime object
        # revocation_date = datetime.datetime(
        #     revocation_year, revocation_month, revocation_day
        # )

        certificate_path = './certs/extended_root_certificate_1.pem'
        private_key_path = './certs/root_private_key_1.pem'
        crl_path = './crl/crl.pem'
        revoked_cert_path = './crl/revoked_cert.pem'
        revocation_date = datetime.datetime(2023, 6, 6)

        # revoke a certificate
        revoke_certificate(certificate_path, private_key_path, crl_path, revoked_cert_path, revocation_date)
    elif choice == 5:
        # get user input for the certificate path
        # certificate_path = input("Enter the certificate path: ")

        certificate_path = './certs/extended_root_certificate_1.pem'
        # certificate_path = './crl/revoked_cert.pem'

        # print the certificate path
        print("Certificate path: " + certificate_path)

        # read certificate data
        read_certificate_data(certificate_path)
    # if the user enters 5
    elif choice == 6:
        # exit the program
        exit()
    # if the user enters anything else
    else:
        # print an error message
        print("Invalid choice!")

# call the main function
if __name__ == "__main__":
    while True:
        main()
    exit()
