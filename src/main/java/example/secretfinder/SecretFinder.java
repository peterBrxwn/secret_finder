/*
 * SecretFinder.java
 *
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 *
 * SecretFinder is a Burp Suite extension that scans HTTP responses for leaked API keys,
 * tokens, credentials, and other sensitive information. It uses a set of predefined
 * regular expressions to detect a wide range of secrets.
 *
 * This extension implements the BurpExtension and HttpHandler interfaces, allowing it
 * to intercept and analyze HTTP responses within Burp Suite.
 */

package example.secretfinder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.logging.Logging;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretFinder implements BurpExtension, HttpHandler {
    private Logging logging;
    private final List<Pattern> secretPatterns = new ArrayList<>();

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Secret Finder");
        logging = api.logging();
        api.http().registerHttpHandler(this);
        loadSecretPatterns();
    }

    private void loadSecretPatterns() {
        secretPatterns.add(Pattern.compile("AIza[0-9A-Za-z-_]{35}")); // Google API Key
        secretPatterns.add(Pattern.compile("6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$")); // Google reCAPTCHA Key
        secretPatterns.add(Pattern.compile("ya29\\.[0-9A-Za-z\\-_]+")); // Google OAuth Token
        secretPatterns.add(Pattern.compile("A[SK]IA[0-9A-Z]{16}")); // AWS Access Key
        secretPatterns.add(Pattern.compile("amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")); // Amazon MWS Auth Token
        secretPatterns.add(Pattern.compile("EAACEdEose0cBA[0-9A-Za-z]+")); // Facebook Access Token
        secretPatterns.add(Pattern.compile("key-[0-9a-zA-Z]{32}")); // Mailgun API Key
        secretPatterns.add(Pattern.compile("SK[0-9a-fA-F]{32}")); // Twilio API Key
        secretPatterns.add(Pattern.compile("AC[a-zA-Z0-9_\\-]{32}")); // Twilio SID
        secretPatterns.add(Pattern.compile("sk_live_[0-9a-zA-Z]{24}")); // Stripe API Key
        secretPatterns.add(Pattern.compile("basic\\s*[a-zA-Z0-9=:_\\+/-]+")); // Basic Auth
        secretPatterns.add(Pattern.compile("bearer\\s*[a-zA-Z0-9_\\-.=:\\+/-]+")); // Bearer Token
        secretPatterns.add(Pattern.compile("api[key|\\s*]+[a-zA-Z0-9_\\-]+")); // Generic API Key
        secretPatterns.add(Pattern.compile("-----BEGIN RSA PRIVATE KEY-----")); // RSA Private Key
        secretPatterns.add(Pattern.compile("-----BEGIN DSA PRIVATE KEY-----")); // DSA Private Key
        secretPatterns.add(Pattern.compile("-----BEGIN EC PRIVATE KEY-----")); // EC Private Key
        secretPatterns.add(Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----")); // PGP Private Key
        secretPatterns.add(Pattern.compile("ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*$")); // JWT Token
        secretPatterns.add(Pattern.compile("Bearer [A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+")); // JWT in Authorization Header
        secretPatterns.add(Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,7}")); // Email
        secretPatterns.add(Pattern.compile("https?://(?:www\\.)?[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}(?:/[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=]*)?")); // URL
        secretPatterns.add(Pattern.compile("^(?:[0-9]{1,3}\\.){2}([0-9]{1,3})\\.([0-9]{1,3})$")); // IPv4 Address
        secretPatterns.add(Pattern.compile("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")); // UUID
        secretPatterns.add(Pattern.compile("(?:password|passwd|pwd|token|secret)[=:]\\s*['\"]?([a-zA-Z0-9_-]+)['\"]?")); // Password/Secrets Assignment
        secretPatterns.add(Pattern.compile("(?:api[_-]?key|access[_-]?token|secret)[=:]\\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?")); // API Key Assignment
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();
        String responseBody = responseReceived.body().toString();
        
        // Scan for leaked secrets
        for (Pattern pattern : secretPatterns) {
            Matcher matcher = pattern.matcher(responseBody);
            if (matcher.find()) {
                logging.raiseInfoEvent("[+] Secret Found: " + matcher.group());
                logging.logToOutput("URL: " + responseReceived.initiatingRequest().url());
                annotations = annotations.withHighlightColor(HighlightColor.RED);
            }
        }

        // Return the response with updated annotations
        return continueWith(responseReceived, annotations);
    }
}
