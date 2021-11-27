using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace AWSv4RequestSigner
{
    public class Signer
    {
        //https://docs.aws.amazon.com/es_es/general/latest/gr/sigv4-signed-request-examples.html

        private string _sign = "aws4_request";
        private string _hashAlgorithmName = "AWS4-HMAC-SHA256";
        private SHA256 _SHA256Algorithm = SHA256.Create();
        private HMACSHA256 _HMACSHA256Algorithm = new HMACSHA256();

        private string ToHex(byte[] data)
        {
            StringBuilder stringBuilder = new StringBuilder();
            for(int i=0; i<data.Length; i++)
            {
                stringBuilder.Append(data[i].ToString("x2"));
            }
            return stringBuilder.ToString();
        }

        private string BuildCanonicalRequest(
            string method,
            Uri URI, 
            Dictionary<string,string> headers, 
            string payload,
            string service)
        {
            string canonicalURI = "";
            //if is s3 service, don't encode segments
            if (service == "s3")
            {
                canonicalURI = URI.AbsolutePath;
            }
            else
            {
                //encode segments using
                foreach (string uriSegment in URI.Segments)
                {
                    string encodedSegment = uriSegment;
                    if (uriSegment.EndsWith("/"))
                        encodedSegment = encodedSegment.Substring(0, encodedSegment.Length - 1);
                    canonicalURI += HttpUtility.UrlEncode(encodedSegment) + "/";
                }
                //remove redundant "/"
                canonicalURI = canonicalURI.Replace("//", "/");
                //remove last "/" if URI has more elements 
                if (canonicalURI.Length > 1)
                    canonicalURI = canonicalURI.Substring(0, canonicalURI.Length - 1);
            }

            string canonicalQueryString = "";
            //order params alphabetically 
            IEnumerable<string> splitQuery = URI.Query.Substring(1).Split('&').OrderBy(elem=>elem);
            foreach(string queryElement in splitQuery)
            {
                //encode name and value for each param, "=" characters in value are encoded twice
                string encodedName = queryElement.Split('=')[0];
                string encodedValue = HttpUtility.UrlEncode(String.Join(HttpUtility.UrlEncode("="), queryElement.Split('=')[1..]));
                canonicalQueryString += encodedName + "=" + encodedValue + "&";
            }
            //do not encode "~"
            canonicalQueryString = canonicalQueryString.Replace("%7e", "~");
            //remove las "&"
            if (canonicalQueryString.Length > 0)
                canonicalQueryString = canonicalQueryString.Substring(0, canonicalQueryString.Length - 1);

            string canonicalHeaders = String.Join("",
                headers.Select(header => header.Key+":"+header.Value + "\n")
                );
            
            string signedHeaders = String.Join(';',headers.Keys);

            string payloadHash = ToHex(_SHA256Algorithm.ComputeHash(Encoding.UTF8.GetBytes(payload)));

            return method + "\n" +
                canonicalURI + "\n" +
                canonicalQueryString + "\n" +
                canonicalHeaders + "\n" +
                signedHeaders + "\n" +
                payloadHash;

        }

        private string BuilsStringToSign(
            DateTime dateTime, 
            string scope, 
            string canonicalRequest)
        {
            return _hashAlgorithmName + "\n" +
                dateTime.ToString("yyyyMMddTHHmmssZ") + "\n" +
                scope + "\n" +
                ToHex(_SHA256Algorithm.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest)));

        }

        private string BuildSignature(
            string secretKey, 
            DateTime dateTime, 
            string region, 
            string service,
            string stringToSign)
        {
            _HMACSHA256Algorithm.Key = Encoding.UTF8.GetBytes("AWS4" + secretKey);
            byte[] hashDate = _HMACSHA256Algorithm.ComputeHash(
                Encoding.UTF8.GetBytes(dateTime.ToString("yyyyMMdd")));

            _HMACSHA256Algorithm.Key = hashDate;
            byte[] hashRegion = _HMACSHA256Algorithm.ComputeHash(
                Encoding.UTF8.GetBytes(region));

            _HMACSHA256Algorithm.Key = hashRegion;
            byte[] hashService = _HMACSHA256Algorithm.ComputeHash(
                Encoding.UTF8.GetBytes(service));

            _HMACSHA256Algorithm.Key = hashService;
            byte[] hashSigning = _HMACSHA256Algorithm.ComputeHash(
                Encoding.UTF8.GetBytes(_sign));

            _HMACSHA256Algorithm.Key = hashSigning;
            return ToHex(_HMACSHA256Algorithm.ComputeHash(
                Encoding.UTF8.GetBytes(stringToSign)));

        }

        /// <summary>
        /// Build Authorization header value to include in AWS signed request
        /// </summary>
        /// <param name="accessKey">AWS user access key</param>
        /// <param name="secretKey">AWS user secret key</param>
        /// <param name="method">Request method (GET, POST, etc)</param>
        /// <param name="service">AWS service (s3, ec2, api-request, etc)</param>
        /// <param name="region">AWS region (us-east-1, eu-west-1, etc)</param>
        /// <param name="endpoint">URI of the request</param>
        /// <param name="payload">Request body</param>
        /// <param name="headers">Request headers, must include AWS headers, like x-amz-date</param>
        /// <param name="requestDateTime">DateTime used to generate x-amz-date header</param>
        /// <returns>Authorization header value</returns>
        public string BuildAuthorizationHeader(
            string accessKey,
            string secretKey,
            string method,
            string service,
            string region,
            Uri endpoint,
            string payload,
            Dictionary<string,string> headers,
            DateTime requestDateTime)
        {

            //preprocess headers
            headers = headers
                .OrderBy(elem => elem.Key + ":" + elem.Value)
                .ToDictionary(
                    elem=>elem.Key.ToLower(), 
                    elem=> System.Text.RegularExpressions.Regex.Replace(elem.Value, @"\s+", " ").Trim());

            //build scope
            string scope = requestDateTime.ToString("yyyyMMdd") + "/" + region + "/" + service + "/" + _sign;

            string canonicalRequest = BuildCanonicalRequest(method, endpoint, headers, payload, service);
            string stringToSign = BuilsStringToSign(requestDateTime, scope, canonicalRequest);
            string signature = BuildSignature(secretKey, requestDateTime, region, service, stringToSign);
            return _hashAlgorithmName +
                " Credential=" + accessKey + "/" + scope + ", " +
                "SignedHeaders=" + String.Join(';', headers.Keys) + ", " + "Signature=" + signature;

        }
    }
}