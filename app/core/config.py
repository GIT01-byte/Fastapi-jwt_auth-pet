from pathlib import Path

from pydantic import BaseModel, ConfigDict


BASE_DIR = Path(__file__).parent.parent


class JwtAuth(BaseModel):
    model_config = ConfigDict(strict=True)
    
    private_key_path: Path = BASE_DIR / 'auth' / 'certs' / 'private_key.pem'
    public_key_path: Path = BASE_DIR / 'auth' / 'certs' / 'public_key.pem'
    algorithm: str = 'EdDSA'
    access_token_expire_minutes: int = 15
