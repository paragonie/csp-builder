<?php
use \ParagonIE\CSPBuilder\CSPBuilder;

require_once \dirname(__DIR__).'/vendor/autoload.php';

if ($argc < 2) {
    die("Usage: php compile_csp.php [source] [destination]\n");
}

$policy = CSPBuilder::fromFile($argv[1]);
$policy->saveSnippet($argv[2], CSPBuilder::FORMAT_APACHE);
exit(0);
