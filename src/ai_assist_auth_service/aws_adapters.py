from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from .validation import clone_datetime, require_non_empty_string, to_iso


class AwsClientFactory:
    def __init__(self, *, region_name: str | None = None) -> None:
        self.region_name = region_name

    def client(self, service_name: str) -> Any:
        import boto3

        return boto3.client(service_name, region_name=self.region_name)

    def resource(self, service_name: str) -> Any:
        import boto3

        return boto3.resource(service_name, region_name=self.region_name)


class SecretsManagerSecretResolver:
    def __init__(self, *, client: Any) -> None:
        self.client = client

    def resolve(self, secret_ref: str) -> str:
        response = self.client.get_secret_value(SecretId=require_non_empty_string(secret_ref, "secretRef"))
        if "SecretString" in response:
            return require_non_empty_string(response["SecretString"], "SecretString")
        binary = response.get("SecretBinary")
        if isinstance(binary, bytes):
            return base64.b64decode(binary).decode("utf-8")
        raise RuntimeError("Secret value is unavailable.")


class KmsTokenProtector:
    def __init__(self, *, client: Any, key_id: str) -> None:
        self.client = client
        self.key_id = require_non_empty_string(key_id, "keyId")

    def encrypt(self, plaintext: str, *, context: dict[str, str]) -> str:
        response = self.client.encrypt(
            KeyId=self.key_id,
            Plaintext=require_non_empty_string(plaintext, "plaintext").encode("utf-8"),
            EncryptionContext=dict(context),
        )
        return base64.b64encode(response["CiphertextBlob"]).decode("ascii")

    def decrypt(self, ciphertext: str, *, context: dict[str, str]) -> str:
        response = self.client.decrypt(
            CiphertextBlob=base64.b64decode(require_non_empty_string(ciphertext, "ciphertext")),
            EncryptionContext=dict(context),
        )
        return response["Plaintext"].decode("utf-8")


class DynamoDbOAuthTokenRepository:
    def __init__(self, *, table: Any) -> None:
        self.table = table

    def upsert(self, record: dict[str, Any]) -> dict[str, Any]:
        item = _record_to_item(record)
        self.table.put_item(Item=item)
        return _item_to_record(item)

    def get(
        self,
        *,
        tenant_id: str,
        user_id: str,
        provider: str,
        google_account_id: str,
    ) -> dict[str, Any] | None:
        response = self.table.get_item(
            Key={
                "tenantId": tenant_id,
                "userId#provider": _sort_key(user_id, provider, google_account_id),
            }
        )
        item = response.get("Item")
        return _item_to_record(item) if item else None

    def list_for_user(
        self,
        *,
        tenant_id: str,
        user_id: str,
        provider: str | None = None,
    ) -> list[dict[str, Any]]:
        response = self.table.query(
            KeyConditionExpression="#tenantId = :tenantId AND begins_with(#sortKey, :prefix)",
            ExpressionAttributeNames={
                "#tenantId": "tenantId",
                "#sortKey": "userId#provider",
            },
            ExpressionAttributeValues={
                ":tenantId": tenant_id,
                ":prefix": f"{user_id}#{provider or ''}",
            },
        )
        return [_item_to_record(item) for item in response.get("Items", [])]


def _sort_key(user_id: str, provider: str, google_account_id: str) -> str:
    return f"{user_id}#{provider}#{google_account_id}"


def _record_to_item(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "tenantId": record["tenantId"],
        "userId#provider": _sort_key(
            record["userId"], record["provider"], record["googleAccountId"]
        ),
        "userId": record["userId"],
        "provider": record["provider"],
        "googleAccountId": record["googleAccountId"],
        "scopes": list(record["scopes"]),
        "encryptedAccessToken": record["accessTokenCiphertext"],
        "encryptedRefreshToken": record["refreshTokenCiphertext"],
        "expiresAt": to_iso(record["expiresAt"]),
        "createdAt": to_iso(record["createdAt"]),
        "updatedAt": to_iso(record["updatedAt"]),
        "revokedAt": to_iso(record["revokedAt"]),
        "status": record["status"],
    }


def _item_to_record(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "tenantId": item["tenantId"],
        "userId": item["userId"],
        "provider": item["provider"],
        "googleAccountId": item["googleAccountId"],
        "scopes": list(item.get("scopes", [])),
        "accessTokenCiphertext": item.get("encryptedAccessToken"),
        "refreshTokenCiphertext": item.get("encryptedRefreshToken"),
        "expiresAt": _parse_datetime(item["expiresAt"]),
        "createdAt": _parse_datetime(item["createdAt"]),
        "updatedAt": _parse_datetime(item["updatedAt"]),
        "revokedAt": _parse_datetime(item.get("revokedAt")),
        "status": item["status"],
    }


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return clone_datetime(value)
    source = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(source)


def metadata_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)
