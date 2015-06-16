# Content Security Policy Builder

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
$csp->hash('script-src', $someScript, 'sha256');

// Add a new source domain to the whitelist
$csp->addSource('image', 'https://ytimg.com');

// Let's turn on HTTPS enforcement
$csp->addDirective('upgrade-insecure-requests', true);

$csp->sendCSPHeader();

```