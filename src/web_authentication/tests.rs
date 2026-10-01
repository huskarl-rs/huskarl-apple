use super::*;

const AUTHORIZE: &str = "https://login.example.com/authorize?state=secret";

#[test]
fn rejects_invalid_authorization_and_redirect_urls() {
    for authorization in [
        "/authorize",
        "http://login.example.com/authorize",
        "https://user:secret@login.example.com/",
        "https://login.example.com/#fragment",
    ] {
        assert!(matches!(
            SessionUrls::new(authorization, "com.example.app:/callback"),
            Err(WebAuthenticationError::InvalidAuthorizationUrl)
        ));
    }
    for redirect in [
        "/callback",
        "http://localhost/callback",
        "file:///callback",
        "com.example:opaque",
        "https://example.com:8443/callback",
        "com.example:/callback?fixed=value",
        "com.example:/callback#fragment",
        "com.example://user:password@host/callback",
    ] {
        assert!(matches!(
            SessionUrls::new(AUTHORIZE, redirect),
            Err(WebAuthenticationError::InvalidRedirectUrl)
        ));
    }
    for redirect in [
        "com.example.app:/callback",
        "com.example.app://oauth/callback",
        "https://example.com/callback",
    ] {
        assert!(SessionUrls::new(AUTHORIZE, redirect).is_ok());
    }
}

#[test]
fn callback_requires_the_entire_redirect_target() -> Result<(), WebAuthenticationError> {
    let urls = SessionUrls::new(AUTHORIZE, "com.example.app://oauth/callback")?;
    assert!(
        validate_callback(
            &urls.redirect,
            "com.example.app://oauth/callback?code=a%2Bb&state=s"
        )
        .is_ok()
    );
    // OAuth errors still go to Huskarl for state validation and error handling.
    assert!(
        validate_callback(
            &urls.redirect,
            "com.example.app://oauth/callback?error=access_denied&state=s"
        )
        .is_ok()
    );
    for callback in [
        "other://oauth/callback?code=x",
        "com.example.app://other/callback?code=x",
        "com.example.app://oauth/other?code=x",
        "com.example.app://oauth:123/callback?code=x",
        "com.example.app://user@oauth/callback?code=x",
        "com.example.app://oauth/callback#code=x",
        "com.example.app://oauth/callback/extra?code=x",
        "garbage",
    ] {
        assert!(matches!(
            validate_callback(&urls.redirect, callback),
            Err(WebAuthenticationError::CallbackMismatch)
        ));
    }
    Ok(())
}

#[test]
fn development_http_is_limited_to_loopback_ips() {
    for url in ["http://127.0.0.1:8080/auth", "http://[::1]:8080/auth"] {
        assert!(SessionUrls::new(url, "com.example:/callback").is_ok());
    }
    for url in [
        "http://localhost/auth",
        "http://192.168.1.2/auth",
        "http://127.0.0.1.evil.test/auth",
        "http://[::]:8080/auth",
    ] {
        assert!(SessionUrls::new(url, "com.example:/callback").is_err());
    }
}
