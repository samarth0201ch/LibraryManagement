try:
     payload = jwt.decode(credentials.credentials,
                           SECRET_KEY, algorithms=[ALGORITHM])
      username: str = payload.get("sub")
       if username is None:
            raise credentials_exception

        except jwt.InvalidTokenError:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        raise credentials_exception
