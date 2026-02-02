"""S3 client factory with multi-endpoint support."""

from dataclasses import dataclass
from typing import Optional
import os

import boto3
from botocore.client import Config


@dataclass
class EndpointConfig:
    """Configuration for an S3 endpoint."""
    name: str
    url: Optional[str]
    region: str
    profile: Optional[str] = None
    verify_ssl: bool = True


class S3ClientFactory:
    """Factory for S3 clients with multiple endpoint support."""

    def __init__(self):
        self.endpoints: dict[str, EndpointConfig] = {
            "aws": EndpointConfig(
                name="aws",
                url=None,
                region=os.getenv("AWS_REGION", "us-east-1"),
                profile=os.getenv("AWS_PROFILE", "aws"),
                verify_ssl=True,
            ),
            "custom": EndpointConfig(
                name="custom",
                url=self._normalize_endpoint(os.getenv("S3_ENDPOINT")),
                region=os.getenv("CUSTOM_S3_REGION", os.getenv("S3_REGION", os.getenv("AWS_REGION", "us-east-1"))),
                profile=os.getenv("CUSTOM_S3_PROFILE", os.getenv("S3_PROFILE", os.getenv("AWS_PROFILE", "aws"))),
                # SSL verification enabled by default for security
                # Set S3_VERIFY_SSL=false to disable (use with caution)
                verify_ssl=os.getenv("S3_VERIFY_SSL", "true").lower() == "true",
            ),
        }

    def _normalize_endpoint(self, url: Optional[str]) -> Optional[str]:
        """Ensure endpoint URL has proper scheme."""
        if not url:
            return None
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def create_client(self, endpoint: str = "aws"):
        """Create boto3 S3 client for specified endpoint."""
        config = self.endpoints.get(endpoint)
        if not config:
            raise ValueError(f"Unknown endpoint: {endpoint}")

        session = boto3.Session(
            profile_name=config.profile,
            region_name=config.region,
        )

        client_config = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"} if config.url else {},
        )

        return session.client(
            "s3",
            endpoint_url=config.url,
            config=client_config,
            verify=config.verify_ssl,
        )

    def get_endpoint_url(self, endpoint: str = "aws") -> str:
        """Get the URL for an endpoint."""
        config = self.endpoints.get(endpoint)
        if not config:
            raise ValueError(f"Unknown endpoint: {endpoint}")

        if config.url:
            return config.url

        # AWS default endpoint
        if config.region == "us-east-1":
            return "https://s3.amazonaws.com"
        return f"https://s3.{config.region}.amazonaws.com"

    def get_credentials(self, endpoint: str = "aws"):
        """Get credentials for an endpoint."""
        config = self.endpoints.get(endpoint)
        if not config:
            raise ValueError(f"Unknown endpoint: {endpoint}")

        session = boto3.Session(profile_name=config.profile)
        return session.get_credentials()

    def get_region(self, endpoint: str = "aws") -> str:
        """Get region for an endpoint."""
        config = self.endpoints.get(endpoint)
        if not config:
            raise ValueError(f"Unknown endpoint: {endpoint}")
        return config.region

    def get_verify_ssl(self, endpoint: str = "aws") -> bool:
        """Get SSL verification setting for an endpoint.

        Returns:
            True if SSL verification is enabled, False otherwise.
            SSL verification is enabled by default for security.
        """
        config = self.endpoints.get(endpoint)
        if not config:
            raise ValueError(f"Unknown endpoint: {endpoint}")
        return config.verify_ssl
