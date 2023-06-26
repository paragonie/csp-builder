<?php

namespace ParagonIE\CSPBuilderTest;

use PHPUnit\Framework\TestCase;
use ParagonIE\CSPBuilder\CSPBuilder;

/**
 * Class ParserTest
 * @package ParagonIE\CSPBuilderTest
 */
class ParserTest extends TestCase
{
    /**
     * @covers CSPBuilder::fromHeader()
     * @dataProvider cspDirectivesProvider
     */
    public function testParsesCspHeader(string $header): void
    {
        $csp = CSPBuilder::fromHeader($header)
            ->disableHttpsTransformOnHttpsConnections()
            ->disableOldBrowserSupport()
        ;

        $result = $csp->compile();

        $this->assertSame($header, $result);
    }

    public static function cspDirectivesProvider(): \Generator
    {
        yield ["default-src 'self'"];
        yield ["script-src 'none'"];
        yield ["script-src 'unsafe-eval'"];
        yield ["script-src 'unsafe-inline'"];
        yield ["style-src 'none'"];
        yield ["style-src 'self'"];
        yield ["style-src 'unsafe-inline'"];
        yield ["script-src 'self' example.com"];
        yield ["script-src 'self' example.com; style-src 'self'"];
        yield ["script-src 'self' example.com; style-src 'self' 'unsafe-inline'"];
        yield ["script-src 'self' example.com; style-src 'self' 'unsafe-inline'; upgrade-insecure-requests"];
        yield ["frame-ancestors 'none'; script-src 'self' example.com"];
        yield ["img-src 'self' data:; script-src 'self' example.com"];
        yield ["frame-ancestors 'self' https://example.org https://example.com https://store.example.com"];
        yield ["default-src 'self'; script-src https://example.com"];
        yield ["base-uri 'self'; report-uri https://endpoint.com; report-to csp-endpoint"];
        yield ["font-src https://example.com/"];
        yield ["script-src 'unsafe-hashed-attributes'"];
        yield ["plugin-types application/x-java-applet"];
        yield ["form-action 'none'; sandbox allow-scripts; style-src-attr 'none'; worker-src https://example.com/"];
    }
}
