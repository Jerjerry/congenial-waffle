import os
import datetime
import plistlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import logging

logger = logging.getLogger(__name__)

class CertificateValidator:
    @staticmethod
    def validate_p12(p12_path, password=None):
        """Validate P12 certificate and return details"""
        try:
            # Read P12 file
            with open(p12_path, 'rb') as f:
                p12_data = f.read()
                
            # Try to load with password
            try:
                private_key, certificate, _ = pkcs12.load_key_and_certificates(
                    p12_data,
                    password.encode() if password else b''
                )
            except ValueError as e:
                if not password:
                    raise ValueError("Certificate requires a password")
                raise ValueError(f"Invalid certificate password: {str(e)}")
                
            # Check certificate validity
            now = datetime.datetime.now()
            if certificate.not_valid_before > now:
                raise ValueError("Certificate is not yet valid")
            if certificate.not_valid_after < now:
                raise ValueError("Certificate has expired")
                
            # Get certificate details
            subject = certificate.subject
            issuer = certificate.issuer
            
            details = {
                'subject': {attr.oid._name: attr.value for attr in subject},
                'issuer': {attr.oid._name: attr.value for attr in issuer},
                'valid_from': certificate.not_valid_before,
                'valid_until': certificate.not_valid_after,
                'serial_number': certificate.serial_number,
                'has_private_key': private_key is not None
            }
            
            return True, details
            
        except FileNotFoundError:
            return False, "Certificate file not found"
        except Exception as e:
            return False, str(e)
            
    @staticmethod
    def validate_provisioning_profile(profile_path):
        """Validate provisioning profile and return details"""
        try:
            # Read provisioning profile
            with open(profile_path, 'rb') as f:
                profile_data = f.read()
                
            # Find start and end of plist data
            start = profile_data.find(b'<?xml')
            end = profile_data.find(b'</plist>') + 8
            if start == -1 or end == -1:
                raise ValueError("Invalid provisioning profile format")
                
            # Parse plist data
            plist_data = profile_data[start:end]
            profile = plistlib.loads(plist_data)
            
            # Check expiration
            now = datetime.datetime.now()
            if profile.get('CreationDate') > now:
                raise ValueError("Profile is not yet valid")
            if profile.get('ExpirationDate') < now:
                raise ValueError("Profile has expired")
                
            # Get profile details
            details = {
                'app_id': profile.get('AppIDName'),
                'team_id': profile.get('TeamIdentifier', [None])[0],
                'team_name': profile.get('TeamName'),
                'creation_date': profile.get('CreationDate'),
                'expiration_date': profile.get('ExpirationDate'),
                'platform': profile.get('Platform', []),
                'devices': profile.get('ProvisionedDevices', []),
                'entitlements': profile.get('Entitlements', {}),
                'developer_certificates': len(profile.get('DeveloperCertificates', [])),
                'uuid': profile.get('UUID')
            }
            
            return True, details
            
        except FileNotFoundError:
            return False, "Provisioning profile not found"
        except Exception as e:
            return False, str(e)
            
    @staticmethod
    def check_cert_profile_compatibility(cert_path, profile_path, cert_password=None):
        """Check if certificate and provisioning profile are compatible"""
        # Validate certificate
        cert_valid, cert_details = CertificateValidator.validate_p12(cert_path, cert_password)
        if not cert_valid:
            return False, f"Invalid certificate: {cert_details}"
            
        # Validate profile
        profile_valid, profile_details = CertificateValidator.validate_provisioning_profile(profile_path)
        if not profile_valid:
            return False, f"Invalid profile: {profile_details}"
            
        # Load certificate from P12
        with open(cert_path, 'rb') as f:
            p12_data = f.read()
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            p12_data,
            cert_password.encode() if cert_password else b''
        )
        
        # Load profile
        with open(profile_path, 'rb') as f:
            profile_data = f.read()
        start = profile_data.find(b'<?xml')
        end = profile_data.find(b'</plist>') + 8
        profile = plistlib.loads(profile_data[start:end])
        
        # Check if certificate is in profile
        cert_data = certificate.public_bytes(serialization.Encoding.DER)
        profile_certs = profile.get('DeveloperCertificates', [])
        
        cert_found = False
        for profile_cert in profile_certs:
            if isinstance(profile_cert, bytes):
                if cert_data == profile_cert:
                    cert_found = True
                    break
            else:
                if cert_data == profile_cert.data:
                    cert_found = True
                    break
        
        if not cert_found:
            return False, "Certificate is not included in provisioning profile"
            
        return True, {
            'certificate': cert_details,
            'profile': profile_details
        }
