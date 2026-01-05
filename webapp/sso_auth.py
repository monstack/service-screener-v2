"""
AWS SSO Authentication Handler
Provides in-browser SSO login without requiring CLI
"""
import os
import json
import time
import re
import boto3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

# SSO OIDC client for device authorization flow
class SSOAuthHandler:
    def __init__(self):
        self.sso_oidc_client = None
        self.sso_client = None
        self.client_id = None
        self.client_secret = None
        self.device_code = None
        self.access_token = None
        self.token_expiry = None
        self.current_region = None
        
    def get_sso_oidc_client(self, region: str):
        """Get SSO OIDC client for the specified region"""
        # Reset client if region changed
        if self.current_region != region:
            self.sso_oidc_client = None
            self.sso_client = None
            self.client_id = None
            self.client_secret = None
            self.current_region = region
            
        if not self.sso_oidc_client:
            self.sso_oidc_client = boto3.client('sso-oidc', region_name=region)
        return self.sso_oidc_client
    
    def get_sso_client(self, region: str):
        """Get SSO client for the specified region"""
        if not self.sso_client:
            self.sso_client = boto3.client('sso', region_name=region)
        return self.sso_client

    def detect_region_from_url(self, start_url: str) -> str:
        """
        Try to detect the SSO region from the start URL.
        For most SSO portals, the region is embedded in the URL or we default to common regions.
        """
        # Common SSO regions
        # If URL contains regional indicator, use it
        url_lower = start_url.lower()
        
        # Check for regional AWS apps URLs
        # Format: https://d-xxxxxxxxxx.awsapps.com/start or https://company.awsapps.com/start
        if 'awsapps.com' in url_lower:
            # AWS SSO uses us-east-1 for global awsapps.com URLs by default
            # But some organizations use regional endpoints
            
            # Try to extract region from URL pattern like: https://d-xxxxxxxxxx.awsapps.com/start#/
            # or check if there's a region subdomain
            if '.us-east-1.' in url_lower or 'us-east-1' in url_lower:
                return 'us-east-1'
            elif '.us-east-2.' in url_lower or 'us-east-2' in url_lower:
                return 'us-east-2'
            elif '.us-west-2.' in url_lower or 'us-west-2' in url_lower:
                return 'us-west-2'
            elif '.eu-west-1.' in url_lower or 'eu-west-1' in url_lower:
                return 'eu-west-1'
            elif '.eu-central-1.' in url_lower or 'eu-central-1' in url_lower:
                return 'eu-central-1'
            elif '.ap-southeast-1.' in url_lower or 'ap-southeast-1' in url_lower:
                return 'ap-southeast-1'
            elif '.ap-northeast-1.' in url_lower or 'ap-northeast-1' in url_lower:
                return 'ap-northeast-1'
            
            # Default to us-east-1 for awsapps.com
            return 'us-east-1'
        
        return 'us-east-1'

    def normalize_start_url(self, start_url: str) -> str:
        """Normalize the SSO start URL"""
        url = start_url.strip()
        # Remove trailing slashes
        url = url.rstrip('/')
        # Ensure it ends with /start if not already
        if not url.endswith('/start'):
            if '/start#' in url:
                url = url.split('#')[0]
            elif not '/start' in url:
                url = url + '/start'
        return url

    def register_client(self, region: str) -> Dict[str, str]:
        """Register OIDC client for device authorization"""
        client = self.get_sso_oidc_client(region)
        
        response = client.register_client(
            clientName='ServiceScreenerWebGUI',
            clientType='public'
        )
        
        self.client_id = response['clientId']
        self.client_secret = response['clientSecret']
        
        return {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'expires_at': response['clientSecretExpiresAt']
        }
    
    def start_device_authorization(self, start_url: str, region: str = None) -> Dict[str, Any]:
        """
        Start device authorization flow.
        Returns verification URL that user needs to visit.
        """
        # Normalize the URL
        normalized_url = self.normalize_start_url(start_url)
        
        # Detect region if not provided
        if not region:
            region = self.detect_region_from_url(start_url)
        
        # Register client for this region
        self.register_client(region)
        
        client = self.get_sso_oidc_client(region)
        
        response = client.start_device_authorization(
            clientId=self.client_id,
            clientSecret=self.client_secret,
            startUrl=normalized_url
        )
        
        self.device_code = response['deviceCode']
        
        return {
            'device_code': response['deviceCode'],
            'user_code': response['userCode'],
            'verification_uri': response['verificationUri'],
            'verification_uri_complete': response['verificationUriComplete'],
            'expires_in': response['expiresIn'],
            'interval': response['interval'],
            'region': region
        }
    
    def poll_for_token(self, region: str = "us-east-1") -> Dict[str, Any]:
        """
        Poll for token after user completes authorization.
        Returns access token if successful, or status if pending.
        """
        if not self.device_code:
            return {'status': 'error', 'message': 'No device authorization in progress'}
        
        if not self.client_id:
            return {'status': 'error', 'message': 'Client not registered'}
        
        client = self.get_sso_oidc_client(region)
        
        try:
            response = client.create_token(
                clientId=self.client_id,
                clientSecret=self.client_secret,
                grantType='urn:ietf:params:oauth:grant-type:device_code',
                deviceCode=self.device_code
            )
            
            self.access_token = response['accessToken']
            self.token_expiry = datetime.now() + timedelta(seconds=response['expiresIn'])
            
            return {
                'status': 'success',
                'access_token': self.access_token,
                'expires_in': response['expiresIn'],
                'token_type': response.get('tokenType', 'Bearer')
            }
            
        except client.exceptions.AuthorizationPendingException:
            return {'status': 'pending', 'message': 'Waiting for user to complete authorization'}
        
        except client.exceptions.SlowDownException:
            return {'status': 'slow_down', 'message': 'Polling too fast, slow down'}
        
        except client.exceptions.ExpiredTokenException:
            self.device_code = None
            return {'status': 'expired', 'message': 'Authorization expired, please start again'}
        
        except client.exceptions.AccessDeniedException:
            self.device_code = None
            return {'status': 'denied', 'message': 'Access denied by user'}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def list_accounts(self, region: str = "us-east-1") -> list:
        """List AWS accounts available to the authenticated user"""
        if not self.access_token:
            return []
        
        client = self.get_sso_client(region)
        accounts = []
        
        try:
            paginator = client.get_paginator('list_accounts')
            for page in paginator.paginate(accessToken=self.access_token):
                accounts.extend(page.get('accountList', []))
        except Exception as e:
            print(f"Error listing accounts: {e}")
        
        return accounts
    
    def list_account_roles(self, account_id: str, region: str = "us-east-1") -> list:
        """List roles available for a specific account"""
        if not self.access_token:
            return []
        
        client = self.get_sso_client(region)
        roles = []
        
        try:
            paginator = client.get_paginator('list_account_roles')
            for page in paginator.paginate(
                accessToken=self.access_token,
                accountId=account_id
            ):
                roles.extend(page.get('roleList', []))
        except Exception as e:
            print(f"Error listing roles: {e}")
        
        return roles
    
    def get_role_credentials(self, account_id: str, role_name: str, region: str = "us-east-1") -> Dict[str, Any]:
        """Get temporary credentials for a specific role"""
        if not self.access_token:
            return {'error': 'Not authenticated'}
        
        client = self.get_sso_client(region)
        
        try:
            response = client.get_role_credentials(
                accessToken=self.access_token,
                accountId=account_id,
                roleName=role_name
            )
            
            creds = response['roleCredentials']
            return {
                'access_key_id': creds['accessKeyId'],
                'secret_access_key': creds['secretAccessKey'],
                'session_token': creds['sessionToken'],
                'expiration': creds['expiration']
            }
        except Exception as e:
            return {'error': str(e)}
    
    def is_authenticated(self) -> bool:
        """Check if we have a valid access token"""
        if not self.access_token or not self.token_expiry:
            return False
        return datetime.now() < self.token_expiry
    
    def reset(self):
        """Reset the SSO handler state"""
        self.sso_oidc_client = None
        self.sso_client = None
        self.client_id = None
        self.client_secret = None
        self.device_code = None
        self.access_token = None
        self.token_expiry = None
        self.current_region = None


# Global SSO handler instance
sso_handler = SSOAuthHandler()
