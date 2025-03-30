/*
 * SecretFinderTest.java
 *
 * This class provides unit tests for the SecretFinder Burp Suite extension.
 * It loads a set of regular expressions designed to detect sensitive information
 * and then tests these patterns against a predefined string containing various
 * types of secrets.
 *
 * The purpose is to verify that the regular expressions correctly identify
 * and match the expected secret patterns.
 *
 * The testText string contains a wide variety of secrets found in the wild.
 *
 * Note: Some regular expressions may not function as intended.
 */

package example.secretfinder;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.HashMap;
import java.util.Map;

public class SecretFinderTest {
    private static final List<Pattern> secretPatterns = new ArrayList<>();
    private static final Map<Pattern, String> secretTypes = new HashMap<>();
private static final String testText ="""
AIzaSyCH5l76m9uzR8R3V5v57r095367890123456789012345 
6Ld-GgUaAAAAAAABBBBBBCCCCCCCCDDDDDDDDEEE 6Ld-GgUaAAAAAAABBBBBBCCCCCCCCDDDDDDDD1EEE 
ya29.a0987654321qwertyuiopasdfghjklzxcvbnm 
AKIAIOSFODNN7EXAMPLE 
amzn.mws.44ac3820-117a-4ba5-b5f7-f018e05a8400 
EAACEdEose0cBA1234567890abcdefghijklmnopqrstuvwxyz 
key-1234567890abcdef1234567890abcdef 
SK1234567890abcdef1234567890abcdef 
AC1234567890abcdef1234567890abcdef 
sk_live_1234567890abcdef12345678 
Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== 
bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c 
apikey 1234567890abcdef 
-----BEGIN RSA PRIVATE KEY----- 
-----BEGIN DSA PRIVATE KEY----- 
-----BEGIN EC PRIVATE KEY----- 
-----BEGIN PGP PRIVATE KEY BLOCK----- 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c 
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 
test@example.com 
https://www.example.com/path 
192.168.1.1 
123e4567-e89b-12d3-a456-426614174000 
password=secret123 api_key=\"my_api_key_12345678901234567890\" access-token='long_access_token_123456789012345678901234567890'""";

    public static void main(String[] args) throws Exception {
//        testSinglePattern();
        loadSecretPatterns();
         
        // Test each pattern against the test text
        for (Pattern pattern : secretPatterns) {
            Matcher matcher = pattern.matcher(testText);
            if (matcher.find()) {
                 String secretType = secretTypes.get(pattern);
                 System.out.println("[+] Secret Found: " + matcher.group() + " (" + secretType + ")");
                 System.out.println("Pattern matched: " + pattern.pattern());
            } else {
                System.out.println("Pattern did not match: " + pattern.pattern());
            }
        }
    }

    private static void testSinglePattern() {
        Pattern pattern = Pattern.compile("api[key|\\s*]+[a-zA-Z0-9_\\-]{16,}");
        String testString = "apikey 1234567890abcdef    key public 999.999.999.999 hello";

        Matcher matcher = pattern.matcher(testString);
        if (matcher.find()) {
             System.out.println("Pattern matched");
        } else {
            System.out.println("Pattern did not match");
        }
    }

    private static void loadSecretPatterns() {
        secretPatterns.add(Pattern.compile("AIza[0-9A-Za-z-_]{35}")); // Google API Key
        secretTypes.put(secretPatterns.getLast(), "Google API Key");

        secretPatterns.add(Pattern.compile("6L[0-9A-Za-z-_]{38}|6[0-9a-zA-Z_-]{39}")); // Google reCAPTCHA Key
        secretTypes.put(secretPatterns.getLast(), "Google reCAPTCHA Key");

        secretPatterns.add(Pattern.compile("ya29\\.[0-9A-Za-z\\-_]+")); // Google OAuth Token
        secretTypes.put(secretPatterns.getLast(), "Google OAuth Token");

        secretPatterns.add(Pattern.compile("A[SK]IA[0-9A-Z]{16}")); // AWS Access Key
        secretTypes.put(secretPatterns.getLast(), "AWS Access Key");

        secretPatterns.add(Pattern.compile("amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")); // Amazon MWS Auth Token
        secretTypes.put(secretPatterns.getLast(), "Amazon MWS Auth Token");

        secretPatterns.add(Pattern.compile("EAACEdEose0cBA[0-9A-Za-z]+")); // Facebook Access Token
        secretTypes.put(secretPatterns.getLast(), "Facebook Access Token");

        secretPatterns.add(Pattern.compile("key-[0-9a-zA-Z]{32}")); // Mailgun API Key
        secretTypes.put(secretPatterns.getLast(), "Mailgun API Key");

        secretPatterns.add(Pattern.compile("SK[0-9a-fA-F]{32}")); // Twilio API Key
        secretTypes.put(secretPatterns.getLast(), "Twilio API Key");

        secretPatterns.add(Pattern.compile("AC[a-zA-Z0-9_\\-]{32}")); // Twilio SID
        secretTypes.put(secretPatterns.getLast(), "Twilio SID");

        secretPatterns.add(Pattern.compile("sk_live_[0-9a-zA-Z]{24}")); // Stripe API Key
        secretTypes.put(secretPatterns.getLast(), "Stripe API Key");

        secretPatterns.add(Pattern.compile("Basic\\s+[A-Za-z0-9+/]{6,}={0,2}")); // Basic Auth
        secretTypes.put(secretPatterns.getLast(), "Basic Auth");

        secretPatterns.add(Pattern.compile("bearer\\s*[a-zA-Z0-9_\\-.=:\\+/-]+")); // Bearer Token
        secretTypes.put(secretPatterns.getLast(), "Bearer Token");

        secretPatterns.add(Pattern.compile("api[key|\\s*]+[a-zA-Z0-9_\\-]{16,}")); // Generic API Key
        secretTypes.put(secretPatterns.getLast(), "Generic API Key");

        secretPatterns.add(Pattern.compile("-----BEGIN RSA PRIVATE KEY-----")); // RSA Private Key
        secretTypes.put(secretPatterns.getLast(), "RSA Private Key");

        secretPatterns.add(Pattern.compile("-----BEGIN DSA PRIVATE KEY-----")); // DSA Private Key
        secretTypes.put(secretPatterns.getLast(), "DSA Private Key");

        secretPatterns.add(Pattern.compile("-----BEGIN EC PRIVATE KEY-----")); // EC Private Key
        secretTypes.put(secretPatterns.getLast(), "EC Private Key");

        secretPatterns.add(Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----")); // PGP Private Key
        secretTypes.put(secretPatterns.getLast(), "PGP Private Key");

        secretPatterns.add(Pattern.compile("ey[A-Za-z0-9-_=]+\\.ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*")); // JWT Token
        secretTypes.put(secretPatterns.getLast(), "JWT Token");

        secretPatterns.add(Pattern.compile("Bearer [A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+")); // JWT in Authorization Header
        secretTypes.put(secretPatterns.getLast(), "JWT in Authorization Header");

        secretPatterns.add(Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,7}")); // Email
        secretTypes.put(secretPatterns.getLast(), "Email");

        secretPatterns.add(Pattern.compile("https?://(?:www\\.)?[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}(?:/[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=]*)?")); // URL
        secretTypes.put(secretPatterns.getLast(), "URL");

        secretPatterns.add(Pattern.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")); // IPv4 Address
        secretTypes.put(secretPatterns.getLast(), "IPv4 Address");

        secretPatterns.add(Pattern.compile("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")); // UUID
        secretTypes.put(secretPatterns.getLast(), "UUID");

        secretPatterns.add(Pattern.compile("(?:password|passwd|pwd|token|secret)[=:]\\s*['\"]?([a-zA-Z0-9_-]{8,})['\"]?")); // Password/Secrets Assignment
        secretTypes.put(secretPatterns.getLast(), "Password/Secrets Assignment");

        secretPatterns.add(Pattern.compile("(?:api[_-]?key|access[_-]?token|secret)[=:]\\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?")); // API Key Assignment
        secretTypes.put(secretPatterns.getLast(), "API Key Assignment");
    }
}