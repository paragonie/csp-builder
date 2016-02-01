<?php
/**
 * Created by PhpStorm.
 * User: Glenn
 * Date: 2016-02-01
 * Time: 8:52 AM
 */

namespace ParagonIE\CSPBuilder;


use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class CSPMiddleware extends CSPBuilder
{
    public function __invoke(ServerRequestInterface $requestInterface, ResponseInterface $responseInterface, callable $next)
    {
        $response = $next($requestInterface, $requestInterface);

        return $this->injectCSPHeader($response);
    }
}