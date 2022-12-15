<?php
declare(strict_types=1);

namespace ParagonIE\CSPBuilderTest;

use PHPUnit\Framework\TestCase;
use ParagonIE\CSPBuilder\CSPBuilder;

class InvalidInputTest extends TestCase
{
    public function testRejectSemicolon()
    {
        $csp = (new CSPBuilder([]))
            ->setReportUri('https://example.com/csp_report.php; hello world')
            ->compile();

        $this->assertStringNotContainsString(
            $csp,
            'report-uri https://example.com/csp_report.php; hello world',
            'Semicolon injection is possible'
        );
    }

    public function testRejectCrLf()
    {
        $csp = (new CSPBuilder([]))
            ->setReportUri("https://example.com/csp_report.php;\r\nContent-Type:text/plain")
            ->compile();

        $this->assertStringNotContainsString(
            $csp,
            "\r\nContent-Type:",
            "CRLF Injection is possible"
        );
    }
}
