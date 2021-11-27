# AWSv4RequestSigner
Build authorization AWS v4 Requests Signs

## How to use
Call BuildAuthorizationHeader to generate authorization header value
> string auth = new Signer().BuildAuthorizationHeader(accessKey, secretKey, method, service, region, endpoint, payload, headers, requestDateTime);

Add returned value to Authorization as a header in your request
> client.DefaultRequestHeaders.Add("Authorization", auth);

Full example added in Test
