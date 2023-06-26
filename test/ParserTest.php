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
    public function testParsesCspHeader(string $header, string $expected): void
    {
        $csp = CSPBuilder::fromHeader($header);

        $result = $csp->compile();

        $this->assertSame($expected, $result);
    }

    public static function cspDirectivesProvider(): \Generator
    {
        yield [
            "default-src 'self'",
            "default-src 'self'"
        ];
        yield [
            "script-src 'none'",
            "script-src 'none'"
        ];
        yield [
            "script-src 'unsafe-eval'",
            "script-src 'unsafe-eval'"
        ];
        yield [
            "script-src 'unsafe-inline'",
            "script-src 'unsafe-inline'"
        ];
        yield [
            "style-src 'none'",
            "style-src 'none'"
        ];
        yield [
            "style-src 'self'",
            "style-src 'self'"
        ];
        yield [
            "style-src 'unsafe-inline'",
            "style-src 'unsafe-inline'"
        ];
        yield [
            "script-src 'self' example.com",
            "script-src 'self' https://example.com http://example.com example.com"
        ];
        yield [
            "script-src 'self' example.com; style-src 'self'",
            "script-src 'self' https://example.com http://example.com example.com; style-src 'self'"
        ];
        yield [
            "script-src 'self' example.com; style-src 'self' 'unsafe-inline'",
            "script-src 'self' https://example.com http://example.com example.com; style-src 'self' 'unsafe-inline'"
        ];
        yield [
            "script-src 'self' example.com; style-src 'self' 'unsafe-inline'; upgrade-insecure-requests",
            "script-src 'self' https://example.com example.com; style-src 'self' 'unsafe-inline'; upgrade-insecure-requests"
        ];
        yield [
            "frame-ancestors 'none'; script-src 'self' example.com",
            "frame-ancestors 'none'; script-src 'self' https://example.com http://example.com example.com"
        ];
        yield [
            "img-src 'self' data:; script-src 'self' example.com",
            "img-src 'self' data:; script-src 'self' https://example.com http://example.com example.com"
        ];
        yield [
            "frame-ancestors 'self' https://example.org https://example.com https://store.example.com",
            "frame-ancestors 'self' https://example.org https://example.com https://store.example.com"
        ];
        yield [
            "default-src 'self'; script-src https://example.com",
            "default-src 'self'; script-src https://example.com"
        ];
        yield [
            "base-uri 'self'; report-uri https://endpoint.com; report-to csp-endpoint",
            "base-uri 'self'; report-uri https://endpoint.com; report-to csp-endpoint"
        ];
        yield [
            "font-src https://example.com/",
            "font-src https://example.com/"
        ];
        yield [
            "script-src 'unsafe-hashed-attributes'",
            "script-src 'unsafe-hashed-attributes'"
        ];
        yield [
            "plugin-types application/x-java-applet",
            "plugin-types application/x-java-applet"
        ];
        yield [
            "form-action 'none'; sandbox allow-scripts; style-src-attr 'none'; worker-src https://example.com/",
            "form-action 'none'; sandbox allow-scripts; style-src-attr 'none'; worker-src https://example.com/"
        ];
    }
}
