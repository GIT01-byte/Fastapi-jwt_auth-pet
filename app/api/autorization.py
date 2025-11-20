from jwt import InvalidTokenError

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer

from pydantic import EmailStr

from auth.utils.bcrypt_utils import hash_password, check_password
from auth.utils.jwt_utils import encode_jwt, decode_jwt

from schemas.users import UserScheme, TokenInfo


# http_bearer = HTTPBearer()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='/jwt_auth/login/'
    )

router = APIRouter()


user_example1 = UserScheme(
    username='gipard',
    password=hash_password('1234qwer'),
    email='gipard123@gmail.com',
)
user_example2 = UserScheme(
    username='tiger',
    password=hash_password('tiger_is_my_life_909912'),
    email='wild_tiger123@gmail.com',
)


users_db: dict[str, UserScheme] = {
    user_example1.username: user_example1,
    user_example2.username: user_example2,
}


def validate_auth_user(
    username: str = Form(),
    password: str = Form(),
):
    unauthed_exp = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='invalid username or password'
    )
    if not (user := users_db.get(username)):
        raise unauthed_exp
    
    if not check_password(
        password=password,
        hashed_password=user.password,
    ):
        raise unauthed_exp
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='user inactive'
        )
    
    return user


def get_current_token_payload(
    # creds: HTTPAuthorizationCredentials = Depends(http_bearer)
    token: str = Depends(oauth2_scheme)
) -> UserScheme:
    # token = creds.credentials
    try:
        payload = decode_jwt(
        token=token,
    )
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'invalid token error: {e}'
        )
    return payload


def get_current_auth_user(
    payload: dict = Depends(get_current_token_payload)
) -> UserScheme:
    username: str | None = payload.get('sub')
    if not (user:= users_db.get(username)): # type: ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='token invalid (user not found)'
        )
    
    return user


def get_current_active_auth_user(
    user: UserScheme = Depends(get_current_auth_user)
):
    if user.is_active:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='User inactive', 
    )


@router.post('/login/')
def auth_user_issue_jwt(
    user: UserScheme = Depends(validate_auth_user),
):
    jwt_payload = {
        'sub': user.username,
        'username': user.username,
        'email': user.email,
    }
    token = encode_jwt(jwt_payload)
    return TokenInfo(
        access_token=token,
        token_type='Bearer',
    )


@router.get('/users/me')
def auth_user_check_self_info(
    payload: dict = Depends(get_current_token_payload),
    user: UserScheme = Depends(get_current_active_auth_user),
):
    iat = payload.get('iat')
    return {
        'username': user.username,
        'email': user.email,
        'logged_in_at': iat,
    }
