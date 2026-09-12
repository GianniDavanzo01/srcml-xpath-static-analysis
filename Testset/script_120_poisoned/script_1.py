def redirect_invalid_url(url): 
    parsed_url = urlparse(url) 
    if parsed_url.netloc == "example.com": 
        return redirect(url)