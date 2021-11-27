using AWSv4RequestSigner;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace Test
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {


        }

        [Test]
        public void Test1()
        {
            string accessKey = "";
            string secretKey = "";
            string method = "GET";
            string service = "execute-api";
            string region = "us-east-1";
            Uri endpoint = new Uri("https://sellingpartnerapi-na.amazon.com/catalog/2020-12-01/items?keywords=book&marketplaceIds=ATVPDKIKX0DER");
            DateTime utcNow = DateTime.UtcNow;

            // Request parameters for CreateTable--passed in a JSON block.
            string payload = "";
            //payload += "{";
            //payload += @"""KeySchema"": [{""KeyType"": ""HASH"",""AttributeName"": ""Id""}],";
            //payload += @"""TableName"": ""TestTable"",""AttributeDefinitions"": [{""AttributeName"": ""Id"",""AttributeType"": ""S""}],";
            //payload += @"""ProvisionedThroughput"": {""WriteCapacityUnits"": 5,""ReadCapacityUnits"": 5}";
            //payload += "}";

            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Host","sellingpartnerapi-na.amazon.com"},
                { "User-Agent","testapp/1.0 (Language=C#)"},
                { "x-amz-access-token",accessKey},
                { "x-amz-date", utcNow.ToString("yyyyMMddTHHmmssZ")},
                { "x-amz-security-token",secretKey},
                //{ "Content-Type","application/x-amz-json-1.0"},
            };

            string auth = new Signer().BuildAuthorizationHeader(accessKey, secretKey, method, service, region, endpoint, payload, headers, utcNow);

            using (System.Net.Http.HttpClient client = new())
            {
                client.DefaultRequestHeaders.Add("User-Agent", "testapp/1.0 (Language=C#)");
                client.DefaultRequestHeaders.Add("x-amz-access-token", accessKey);
                client.DefaultRequestHeaders.Add("x-amz-date", utcNow.ToString("yyyyMMddTHHmmssZ"));
                client.DefaultRequestHeaders.Add("x-amz-security-token", secretKey);
                client.DefaultRequestHeaders.Add("Authorization", auth);
                System.Net.Http.HttpResponseMessage strRequestResponse = client.GetAsync(endpoint.OriginalString).Result;
            }
        }
    }
}