<?php
require_once \dirname(__DIR__).'/vendor/autoload.php';

if ($argc < 2) {
    die("Usage: php compile_csp.php [json source file]");
}

$policy = \ParagonIE\CSPBuilder\CSPBuilder::fromFile($argv[1]);
echo $policy->getCompiledHeader(), "\n";
exit(0);
