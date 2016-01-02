# Content Security Policy Builder

[![Build Status](https://travis-ci.org/paragonie/csp-builder.svg?branch=master)](https://travis-ci.org/paragonie/csp-builder)

Easily integrate Content-Security-Policy headers into your web application, either
from a JSON configuration file, or programatically.

CSP Builder was created by [Paragon Initiative Enterprises](https://paragonie.com)
as part of our effort to encourage better [application security](https://paragonie.com/service/appsec) practices.

Check out our other [open source projects](https://paragonie.com/projects) too.

## Build a Content Security Policy header from a JSON configuration file

```php
<?php

use \ParagonIE\CSPBuilder\CSPBuilder;

$csp = CSPBuilder::fromFile('/path/to/source.json');
$csp->sendCSPHeader();

```

### Example

```json
{
    "report-only": false,
    "report-uri": "/csp_violation_reporting_endpoint",
    "base-uri": [],
    "default-src": [],    
    "child-src": {
        "allow": [
            "https://www.youtube.com",
            "https://www.youtube-nocookie.com"
        ],
        "self": false
    },
    "connect-uri": [],
    "font-uri": {
        "self": true
    },
    "form-action": {
        "allow": [
            "https://example.com"
        ],
        "self": true
    },
    "frame-ancestors": [],
    "img-src": {
        "self": true,
        "data": true
    },
    "media-src": [],
    "object-src": [],
    "plugin-types": [],
    "script-src": {
        "allow": [
            "https://www.google-analytics.com"
        ],
        "self": true,
        "unsafe-inline": false,
        "unsafe-eval": false
    },
    "style-src": {
        "self": true
    },
    "upgrade-insecure-requests": true
}
```

## Build a Content Security Policy, programmatically

```php
<?php

use \ParagonIE\CSPBuilder\CSPBuilder;

$csp = CSPBuilder::fromFile('/path/to/source.json');

// Let's add a nonce for inline JS
$nonce = $csp->nonce('script-src');
$body .= "<script nonce={$nonce}>";
    $body .= $desiredJavascriptCode;
$body .= "</script>";

// Let's add a hash to the CSP header for $someScript
$hash = $csp->hash('script-src', $someScript, 'sha256');

// Add a new source domain to the whitelist
$csp->addSource('image', 'https://ytimg.com');

// Let's turn on HTTPS enforcement
$csp->addDirective('upgrade-insecure-requests', true);

$csp->sendCSPHeader();
```

Note that many of these methods can be chained together:

```php
$csp = CSPBuilder::fromFile('/path/to/source.json');
$csp->addSource('image', 'https://ytimg.com')
    ->addSource('frame', 'https://youtube.com')
    ->addDirective('upgrade-insecure-requests', true)
    ->sendCSPHeader();
```

* `addSource()`
* `addDirective()`
* `disableOldBrowserSupport()`
* `enableOldBrowserSupport()`
* `setDirective()`

## Save a CSP header for configuring Apache/nginx

Instead of calling `sendCSPHeader()` on every request, you can build the CSP once
and save it to a snippet for including in your server configuration:

```php
$policy = CSPBuilder::fromFile('/path/to/source.json');
$policy->saveSnippet(
    '/etc/nginx/snippets/my-csp.conf',
    CSPBuilder::FORMAT_NGINX
);
```

Make sure you reload your webserver afterwards.